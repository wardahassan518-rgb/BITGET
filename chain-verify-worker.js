// ══════════════════════════════════════════════════════════
//  chain-verify-worker.js — SCALE-FIX 3
//  Web Worker for off-main-thread SHA-256 chain verification.
//
//  USAGE (from chain-integrity.html):
//    const worker = new Worker('chain-verify-worker.js');
//    worker.postMessage({ transactions, salt });
//
//  MESSAGES RECEIVED:
//    { transactions: Array, salt: string }
//
//  MESSAGES SENT (posted back to main thread):
//    { type: 'progress', current: number, total: number, pct: number }
//    { type: 'complete', result: ChainVerifyResult }
//    { type: 'error',   message: string }
//
//  CONSTRAINTS:
//    - No changes to hash payload logic; mirrors hash-engine.js exactly.
//    - No DB access — caller loads transactions and passes them in.
//    - Uses crypto.subtle (available in Workers on all modern browsers).
// ══════════════════════════════════════════════════════════

'use strict';

// ── Constants (must match hash-engine.js exactly) ─────────
const HASH_VERSION_V1 = 'DEMS-v1';
const HASH_VERSION_V2 = 'DEMS-v2';
const GENESIS_HASH    = '0'.repeat(64);
const SALT_LEGACY     = 'DEMS_CHAIN_SALT_2024';

// ── SHA-256 (same implementation as hash-engine.js) ───────
async function sha256(input) {
  const encoded = new TextEncoder().encode(input);
  const buffer  = await crypto.subtle.digest('SHA-256', encoded);
  const bytes   = Array.from(new Uint8Array(buffer));
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Payload builders (verbatim from hash-engine.js) ───────
function buildHashPayloadV1(record, prevHash, salt) {
  const fields = [
    HASH_VERSION_V1,
    record.receipt_number  || '',
    record.txn_type        || '',
    String(record.amount_pkr    || 0),
    String(record.exchange_rate || 0),
    String(record.amount_usdt   || 0),
    record.client_name     || '',
    record.client_cnic     || '',
    record.bank_name       || '',
    record.bank_last4      || '',
    record.order_id        || '',
    record.payment_ref     || '',
    record.timestamp,
    String(record.chain_index),
    prevHash,
    salt || SALT_LEGACY
  ];
  return fields.join('|');
}

function buildHashPayloadV2(record, prevHash, salt) {
  const fields = [
    HASH_VERSION_V2,
    record.receipt_number  || '',
    record.txn_type        || '',
    String(record.amount_pkr    || 0),
    String(record.exchange_rate || 0),
    String(record.amount_usdt   || 0),
    record.cost_rate  == null ? 'null' : String(record.cost_rate),
    record.profit_pkr == null ? 'null' : String(record.profit_pkr),
    record.client_name     || '',
    record.client_cnic     || '',
    record.bank_name       || '',
    record.bank_last4      || '',
    record.order_id        || '',
    record.payment_ref     || '',
    record.timestamp,
    String(record.chain_index),
    prevHash,
    salt || SALT_LEGACY
  ];
  return fields.join('|');
}

function buildHashPayloadForRecord(record, prevHash, salt) {
  const ver = (record.hash_version || '').trim();
  if (ver === HASH_VERSION_V1 || ver === 'DEMS-v1') {
    return buildHashPayloadV1(record, prevHash, salt);
  }
  return buildHashPayloadV2(record, prevHash, salt);
}

// ── verifyRecord (mirrors hash-engine.js SEC-FIX 6 logic) ─
async function verifyRecord(txn, salt) {
  const isV1 = (txn.hash_version || '').trim() === HASH_VERSION_V1;

  // Fast path for definitive pre-migration records (DEMS-v1).
  if (isV1) {
    const payload      = buildHashPayloadV1(txn, txn.prev_hash, SALT_LEGACY);
    const computedHash = await sha256(payload);
    const valid        = computedHash === txn.hash;
    return { valid, computedHash, legacySalt: true };
  }

  // Standard path: try current install salt first.
  const payload      = buildHashPayloadForRecord(txn, txn.prev_hash, salt);
  const computedHash = await sha256(payload);

  if (computedHash === txn.hash) {
    return { valid: true, computedHash, legacySalt: false };
  }

  // Fallback: retry with SALT_LEGACY for pre-migration v2 records.
  if (salt !== SALT_LEGACY) {
    const legacyPayload = buildHashPayloadForRecord(txn, txn.prev_hash, SALT_LEGACY);
    const legacyHash    = await sha256(legacyPayload);

    if (legacyHash === txn.hash) {
      return { valid: true, computedHash: legacyHash, legacySalt: true };
    }
  }

  // Both salt attempts failed.
  return { valid: false, computedHash, legacySalt: false };
}

// ── verifyChainLink ────────────────────────────────────────
function verifyChainLink(txn, prevTxn) {
  const expected = prevTxn ? prevTxn.hash : GENESIS_HASH;
  return expected === txn.prev_hash;
}

// ── Main verification loop ─────────────────────────────────
async function runVerification(transactions, salt) {
  const total   = transactions.length;
  const results = [];
  let   broken  = false;
  let   firstBreakAt = null;
  const startTime = Date.now();

  if (total === 0) {
    self.postMessage({
      type: 'complete',
      result: {
        status          : 'EMPTY',
        message         : 'No transactions in chain yet.',
        total           : 0,
        verified        : 0,
        tampered        : 0,
        brokenLinks     : 0,
        chainIntact     : true,
        verificationTime: 0,
        results         : []
      }
    });
    return;
  }

  // Post initial progress immediately so the UI bar appears.
  self.postMessage({ type: 'progress', current: 0, total, pct: 0 });

  for (let i = 0; i < total; i++) {
    const txn     = transactions[i];
    const prevTxn = i > 0 ? transactions[i - 1] : null;

    const hashCheck = await verifyRecord(txn, salt);
    const linkValid  = verifyChainLink(txn, prevTxn);
    const recordOk   = hashCheck.valid && linkValid;

    if (!recordOk && !broken) {
      broken       = true;
      firstBreakAt = txn.chain_index;
    }

    results.push({
      chainIndex    : txn.chain_index,
      receiptNumber : txn.receipt_number,
      timestamp     : txn.timestamp,
      hashValid     : hashCheck.valid,
      linkValid     : linkValid,
      intact        : recordOk,
      // Truncate for network-transfer efficiency (mirrors main thread behaviour).
      storedHash    : txn.hash.substring(0, 16) + '…',
      computedHash  : hashCheck.computedHash.substring(0, 16) + '…'
    });

    // Post progress every record; main thread can throttle rendering.
    const pct = Math.round(((i + 1) / total) * 100);
    self.postMessage({ type: 'progress', current: i + 1, total, pct });
  }

  const tampered    = results.filter(r => !r.intact).length;
  const intact      = results.filter(r =>  r.intact).length;
  const brokenLinks = results.filter(r => !r.linkValid).length;
  const status      = tampered === 0 ? 'INTACT' : 'COMPROMISED';

  self.postMessage({
    type: 'complete',
    result: {
      status,
      message: tampered === 0
        ? `All ${total} transactions verified. Chain is intact.`
        : `WARNING: ${tampered} tampered record(s) detected. First breach at chain index #${firstBreakAt}.`,
      total,
      verified        : intact,
      tampered,
      brokenLinks,
      chainIntact     : tampered === 0,
      firstBreakAt,
      verificationTime: Date.now() - startTime,
      results
    }
  });
}

// ── Message handler ────────────────────────────────────────
self.onmessage = async (event) => {
  const { transactions, salt } = event.data;

  if (!Array.isArray(transactions)) {
    self.postMessage({ type: 'error', message: 'transactions must be an array.' });
    return;
  }

  try {
    await runVerification(transactions, salt || SALT_LEGACY);
  } catch (e) {
    self.postMessage({ type: 'error', message: e.message || String(e) });
  }
};
