// ══════════════════════════════════════════════════════════
//  hash-engine.js — Tamper-Proof Core Engine
//  Digital Exchange Management System — Phase 02
// ══════════════════════════════════════════════════════════

const HashEngine = (() => {

  const HASH_VERSION    = 'DEMS-v2';   // current version — includes cost_rate & profit_pkr
  const HASH_VERSION_V1 = 'DEMS-v1';  // legacy version — for verifying pre-profit records
  const GENESIS_HASH    = '0'.repeat(64);

  // ── SEC-FIX 6: Per-install chain salt ───────────────────
  //
  // SALT is now loaded from app_settings('chain_salt') at runtime.
  // SALT_LEGACY is the old hardcoded value — used ONLY when no
  // chain_salt exists in the DB (i.e. pre-migration installs).
  const SALT_LEGACY = 'DEMS_CHAIN_SALT_2024';

  let _chainSalt = null;  // cached after first DB read

  async function _loadChainSalt() {
    if (_chainSalt !== null) return _chainSalt;
    try {
      const row = await DB.get(`SELECT value FROM app_settings WHERE key = 'chain_salt'`);
      _chainSalt = (row && row.value) ? row.value : SALT_LEGACY;
    } catch {
      _chainSalt = SALT_LEGACY;
    }
    return _chainSalt;
  }

  async function _getSalt() { return _loadChainSalt(); }

  function _invalidateSaltCache() { _chainSalt = null; }

  async function sha256(input) {
    const encoded = new TextEncoder().encode(input);
    const buffer  = await crypto.subtle.digest('SHA-256', encoded);
    const bytes   = Array.from(new Uint8Array(buffer));
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── buildHashPayload ────────────────────────────────────
  //
  // Builds the pipe-delimited string that gets SHA-256'd into the
  // record's `hash` field.
  //
  // v1 (DEMS-v1): original field order — no profit fields.
  //               Used for all records inserted before profit tracking.
  //
  // v2 (DEMS-v2): adds cost_rate and profit_pkr immediately after
  //               amount_usdt.  NULL values are serialised as the
  //               string 'null' so the payload is unambiguous.
  //
  // Always call buildHashPayloadV2() for NEW records.
  // Call buildHashPayloadForRecord() when verifying an existing record
  // — it picks v1 or v2 based on the HASH_VERSION stored in the row.
  //
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
      HASH_VERSION,
      record.receipt_number  || '',
      record.txn_type        || '',
      String(record.amount_pkr    || 0),
      String(record.exchange_rate || 0),
      String(record.amount_usdt   || 0),
      // profit fields — null when not supplied
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

  // Picks the correct payload builder based on which HASH_VERSION is
  // stamped on the record itself — so old rows always verify under v1
  // and new rows always verify under v2, regardless of the current
  // HASH_VERSION constant above.
  function buildHashPayloadForRecord(record, prevHash, salt) {
    const ver = (record.hash_version || '').trim();
    if (ver === HASH_VERSION_V1 || ver === 'DEMS-v1') {
      return buildHashPayloadV1(record, prevHash, salt);
    }
    // Default to v2 for new records and any future versions.
    return buildHashPayloadV2(record, prevHash, salt);
  }

  // Convenience alias used by new-record paths (always v2 going forward).
  function buildHashPayload(record, prevHash, salt) {
    return buildHashPayloadV2(record, prevHash, salt);
  }

  function getDeviceTimestamp() {
    // Renamed from getServerTimestamp — this app has no backend, so this is
    // always the LOCAL DEVICE clock, never a true server time. See
    // checkNetworkTime() below for the best-effort network time comparison
    // used to flag transactions where the device clock could not be verified.
    return new Date().toISOString();
  }

  // ════════════════════════════════════════════════════════
  //  NETWORK TIME CHECK (best-effort, never blocking)
  //
  //  This app has no backend, so there is no authoritative server
  //  time to stamp records with. As an interim integrity measure,
  //  on submit we attempt to fetch the current time from a public
  //  time API and compare it to the device clock. This does NOT
  //  change what gets stored as the record's timestamp — it only
  //  tells us whether the device clock looked trustworthy at the
  //  moment of submission, which gets recorded via clock_unverified.
  // ════════════════════════════════════════════════════════

  const CLOCK_DRIFT_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes
  // UX-FIX 4: Multi-source time API with per-source timeout and sequential fallback.
  // If worldtimeapi.org is unavailable, timeapi.io is tried automatically.
  // fetchNetworkTime() throws only if ALL sources fail — callers handle that via
  // checkNetworkTime() which never throws and sets checked:false on any failure.
  const TIME_APIS = [
    {
      url  : 'https://worldtimeapi.org/api/timezone/Etc/UTC',
      parse: d => {
        if (!d || !d.utc_datetime) throw new Error('worldtimeapi: missing utc_datetime');
        return new Date(d.utc_datetime).getTime();
      }
    },
    {
      url  : 'https://timeapi.io/api/time/current/zone?timeZone=UTC',
      parse: d => {
        if (!d || !d.dateTime) throw new Error('timeapi.io: missing dateTime');
        return new Date(d.dateTime).getTime();
      }
    }
  ];
  const TIME_API_TIMEOUT_MS = 3000; // per-source timeout (ms)

  async function fetchNetworkTime() {
    const errors = [];
    for (const api of TIME_APIS) {
      const ctrl = new AbortController();
      const tid  = setTimeout(() => ctrl.abort(), TIME_API_TIMEOUT_MS);
      try {
        const res = await fetch(api.url, { signal: ctrl.signal, cache: 'no-store' });
        clearTimeout(tid);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        return api.parse(data); // returns epoch ms on success
      } catch (e) {
        clearTimeout(tid);
        errors.push(`${api.url}: ${e.message}`);
        // continue to next source
      }
    }
    throw new Error('All time APIs unavailable. Tried: ' + errors.join('; '));
  }

  /**
   * checkNetworkTime()
   * Best-effort comparison of the device clock against a public time API.
   * NEVER throws — always resolves to a status object so callers can
   * proceed with the transaction regardless of outcome.
   *
   * Returns one of:
   *   { checked: true,  drift_ok: true,  driftMs }   — clock looks fine
   *   { checked: true,  drift_ok: false, driftMs }   — clock is off by >5min
   *   { checked: false, reason }                     — network check unavailable (offline, timeout, API error)
   */
  async function checkNetworkTime() {
    try {
      const beforeLocal = Date.now();
      const networkMs   = await fetchNetworkTime();
      const afterLocal   = Date.now();

      // Account for round-trip latency by comparing against the midpoint
      // of when the request was sent/received.
      const localMidpoint = (beforeLocal + afterLocal) / 2;
      const driftMs = Math.abs(localMidpoint - networkMs);

      return {
        checked  : true,
        drift_ok : driftMs <= CLOCK_DRIFT_THRESHOLD_MS,
        driftMs  : Math.round(driftMs)
      };
    } catch (e) {
      // Offline, request timed out, CORS blocked, API down, etc. — this is
      // expected and must never block the transaction.
      return {
        checked : false,
        reason  : e.message || 'Network time check failed'
      };
    }
  }

  async function getChainState() {
    try {
      const last = await DB.get(
        `SELECT hash, chain_index
         FROM transactions
         ORDER BY chain_index DESC
         LIMIT 1`
      );

      if (!last) {
        return {
          prevHash  : GENESIS_HASH,
          nextIndex : 0
        };
      }

      return {
        prevHash  : last.hash,
        nextIndex : last.chain_index + 1
      };
    } catch (e) {
      console.error('[HashEngine] getChainState error:', e);
      return {
        prevHash  : GENESIS_HASH,
        nextIndex : 0
      };
    }
  }

  async function logVerification(receiptNumber, result) {
    try {
      await DB.run(
        `INSERT INTO verification_log (receipt_number, verified_at, result, verifier_ip, user_agent)
         VALUES (?, ?, ?, ?, ?)`,
        [receiptNumber || '', new Date().toISOString(), result, '', navigator.userAgent.substring(0, 120)]
      );
    } catch (e) {
      console.warn('[HashEngine] verification_log write skipped:', e.message);
    }
  }

  /**
   * subtractClientVolume(original)
   *
   * Called when a transaction is voided. Reverses the client KYC stat bump
   * that syncClientForTransaction() applied when the original transaction
   * was first inserted — decrementing total_txns and total_volume_pkr by
   * exactly the original transaction's contribution. Void entries must
   * NEVER be passed through syncClientForTransaction() themselves (that
   * would add the void as a brand-new transaction and double-count the
   * client's volume); this function is the correct counterpart for voids.
   * Floors at zero so a client record can never go negative even if stats
   * were already out of sync.
   */
  async function subtractClientVolume(original) {
    if (!original.client_name && !original.client_cnic) return;

    const cnic = (original.client_cnic || '').trim();
    const name = (original.client_name || '').trim();
    const amount = parseFloat(original.amount_pkr) || 0;

    let client = null;
    if (cnic) {
      client = await DB.get('SELECT * FROM clients WHERE cnic = ?', [cnic]);
    } else if (name) {
      client = await DB.get("SELECT * FROM clients WHERE full_name = ? AND cnic IS NULL", [name]);
    }

    if (client) {
      const newTxns = Math.max(0, (client.total_txns || 0) - 1);
      const newVol  = Math.max(0, (client.total_volume_pkr || 0) - amount);
      await DB.run(
        'UPDATE clients SET total_txns = ?, total_volume_pkr = ?, updated_at = ? WHERE id = ?',
        [newTxns, newVol, new Date().toISOString(), client.id]
      );
    }
  }

  return {

    /**
     * checkDeviceClock()
     * Public wrapper around the network time check, for UI callers
     * (new-transaction.html) that want to warn the user BEFORE locking
     * a transaction. Never throws, never blocks.
     */
    async checkDeviceClock() {
      return await checkNetworkTime();
    },

    /**
     * getChainSalt()
     * SCALE-FIX 3: Public read-only accessor for the per-install chain
     * salt. Needed so chain-integrity.html can hand the salt to
     * chain-verify-worker.js (a separate execution context that has no
     * access to this module's private _getSalt()/_chainSalt cache).
     * Does NOT change hash logic — it exposes the exact same value
     * _getSalt() already uses internally for verifyRecord().
     */
    async getChainSalt() {
      return await _getSalt();
    },

    async prepareRecord(formData, clockCheck = null) {
      const timestamp = getDeviceTimestamp();
      const receiptNumber = await DB.getNextReceiptNumber();
      const { prevHash, nextIndex } = await getChainState();

      // clock_unverified = 1 whenever the network time check could not
      // confirm the device clock was within tolerance — either because the
      // check failed outright (offline/timeout/API error) or because it
      // succeeded but found the clock drifted beyond the 5-minute threshold.
      // It stays 0 only when the check ran AND found the clock to be fine.
      const clockUnverified = (!clockCheck || !clockCheck.checked || !clockCheck.drift_ok) ? 1 : 0;

      // ── cost_rate & profit_pkr (optional profit-tracking fields) ────────
      // parseFloat('') → NaN; we store null in that case so the DB column
      // stays NULL (not 0, which is a valid — if unusual — break-even value).
      //
      // Auto-calculation of profit_pkr:
      //   When the user supplied a cost_rate but left profit_pkr blank the
      //   engine calculates it here so the stored value is always consistent
      //   with what the UI suggestion shows, even if the user dismissed it.
      //
      //   Formula (mirrors suggestProfit() in new-transaction.html):
      //     buy  (client sells USDT to us):   profit = (cost_rate − exchange_rate) × amount_usdt
      //     sell (client buys USDT from us):  profit = (exchange_rate − cost_rate) × amount_usdt
      //
      //   Result is rounded to 2 decimal places and guarded against
      //   Infinity / NaN before storage — a bad float never reaches the DB.
      const costRateRaw  = parseFloat(formData.cost_rate);
      const profitPkrRaw = parseFloat(formData.profit_pkr);

      const costRate  = isNaN(costRateRaw)  ? null : costRateRaw;
      let   profitPkr = isNaN(profitPkrRaw) ? null : profitPkrRaw;

      if (profitPkr === null && costRate !== null) {
        // Only auto-calculate when we have enough data
        const exchRate = parseFloat(formData.exchange_rate) || 0;
        const amtUsdt  = parseFloat(formData.amount_usdt)   || 0;

        if (exchRate > 0 && amtUsdt > 0) {
          const raw = formData.txn_type === 'buy'
            ? (costRate - exchRate) * amtUsdt   // buy: profit when LP rate > rate paid to client
            : (exchRate - costRate) * amtUsdt;  // sell: profit when rate charged to client > LP rate

          // Round to 2dp to avoid floating-point noise; guard Infinity/NaN
          const rounded = Math.round(raw * 100) / 100;
          profitPkr = isFinite(rounded) ? rounded : null;
        }
      }

      const record = {
        receipt_number  : receiptNumber,
        order_id        : (formData.order_id        || '').trim(),
        txn_type        : formData.txn_type,
        amount_pkr      : parseFloat(formData.amount_pkr)      || 0,
        exchange_rate   : parseFloat(formData.exchange_rate)   || 0,
        amount_usdt     : parseFloat(formData.amount_usdt)     || 0,
        cost_rate       : costRate,
        profit_pkr      : profitPkr,
        client_name     : (formData.client_name     || '').trim(),
        client_cnic     : (formData.client_cnic     || '').trim(),
        bank_name       : (formData.bank_name       || '').trim(),
        bank_last4      : (formData.bank_last4      || '').trim(),
        payment_ref     : (formData.payment_ref     || '').trim(),
        notes           : (formData.notes           || '').trim(),
        screenshot_path : (formData.screenshot_path || '').trim(),
        timestamp       : timestamp,
        chain_index     : nextIndex,
        prev_hash       : prevHash,
        is_locked       : 1,
        clock_unverified: clockUnverified,
        hash_version    : HASH_VERSION   // stamped on the record for verifyRecord() to pick correctly
      };

      const payload     = buildHashPayload(record, prevHash, await _getSalt());  // always v2 for new records
      record.hash       = await sha256(payload);

      return record;
    },

    async insertTransaction(formData, clockCheck = null) {
      try {
        const validation = this.validateFormData(formData);
        if (!validation.valid) {
          return { success: false, error: validation.error };
        }

        const record = await this.prepareRecord(formData, clockCheck);
        let attachmentId = null;

        // ── ATOMIC WRITE ──────────────────────────────────────────────────
        // INSERT the transaction row, sync the client KYC stats, and (if a
        // screenshot was uploaded) save the attachment — all inside one
        // SQLite BEGIN/COMMIT via DB.transaction(). If any step throws, the
        // whole block rolls back so we never end up with a chained
        // transaction that has no matching client stats, or a client stat
        // bump with no transaction row behind it.
        await DB.transaction(async () => {
          const insertResult = await DB.run(
            `INSERT INTO transactions (
              receipt_number, order_id, txn_type,
              amount_pkr, exchange_rate, amount_usdt,
              cost_rate, profit_pkr,
              client_name, client_cnic,
              bank_name, bank_last4, payment_ref,
              notes, screenshot_path,
              timestamp, hash, prev_hash, chain_index, is_locked, clock_unverified,
              hash_version
            ) VALUES (
              ?, ?, ?,
              ?, ?, ?,
              ?, ?,
              ?, ?,
              ?, ?, ?,
              ?, ?,
              ?, ?, ?, ?, ?, ?,
              ?
            )`,
            [
              record.receipt_number,  record.order_id,      record.txn_type,
              record.amount_pkr,      record.exchange_rate,  record.amount_usdt,
              record.cost_rate,       record.profit_pkr,
              record.client_name,     record.client_cnic,
              record.bank_name,       record.bank_last4,    record.payment_ref,
              record.notes,           record.screenshot_path,
              record.timestamp,       record.hash,          record.prev_hash,
              record.chain_index,     record.is_locked,      record.clock_unverified,
              record.hash_version
            ]
          );

          record.id = insertResult.lastInsertRowid;

          // Auto-synchronize client KYC record representing transaction data
          await this.syncClientForTransaction(record);

          // Persist the screenshot blob (if any) into the attachments table
          // and point screenshot_path/attachment_id at it — same atomic
          // unit as the insert + client sync above.
          if (formData.attachmentData && record.id) {
            const mimeMatch = formData.attachmentData.match(/^data:([^;]+);base64,/);
            const mimeType  = mimeMatch ? mimeMatch[1] : 'image/jpeg';
            attachmentId = await DB.saveAttachment(record.id, mimeType, formData.attachmentData);
            await DB.run(
              `UPDATE transactions SET screenshot_path = ?, attachment_id = ? WHERE id = ?`,
              [`attachment:${attachmentId}`, attachmentId, record.id]
            );
            record.screenshot_path = `attachment:${attachmentId}`;
            record.attachment_id   = attachmentId;
          }
        });

        AuditLog.add(
          'TRANSACTION_ADDED',
          `Receipt: ${record.receipt_number} | Type: ${record.txn_type.toUpperCase()} | PKR: ${record.amount_pkr.toLocaleString()} | Chain: #${record.chain_index}` +
          (record.clock_unverified ? ' | ⚠ clock_unverified' : '')
        );

        return {
          success       : true,
          record        : record,
          receiptNumber : record.receipt_number,
          txnId         : record.id,
          attachmentId  : attachmentId
        };

      } catch (e) {
        console.error('[HashEngine] insertTransaction error:', e);
        AuditLog.add('TRANSACTION_ERROR', `Insert failed: ${e.message}`);
        return { success: false, error: e.message };
      }
    },

    async syncClientForTransaction(record) {
      if (!record.client_name && !record.client_cnic) {
        return;
      }

      const name = (record.client_name || '').trim();
      const cnic = (record.client_cnic || '').trim();
      const amount = parseFloat(record.amount_pkr) || 0;
      const t = record.timestamp;

      let client = null;
      if (cnic) {
        client = await DB.get(`SELECT * FROM clients WHERE cnic = ?`, [cnic]);
      } else if (name) {
        client = await DB.get(`SELECT * FROM clients WHERE full_name = ? AND cnic IS NULL`, [name]);
      }

      if (client) {
        // Update existing client stats
        const totalTxns = (client.total_txns || 0) + 1;
        const totalVolume = (client.total_volume_pkr || 0) + amount;
        const firstTxn = client.first_txn_date || t;
        const lastTxn = t;

        const bName  = record.bank_name  || client.bank_name  || '';
        const bLast4 = record.bank_last4 || client.bank_last4 || '';

        await DB.run(
          `UPDATE clients SET
             full_name = COALESCE(NULLIF(full_name, ''), ?),
             total_txns = ?,
             total_volume_pkr = ?,
             first_txn_date = ?,
             last_txn_date = ?,
             bank_name = ?,
             bank_last4 = ?,
             updated_at = ?
           WHERE id = ?`,
          [name || client.full_name, totalTxns, totalVolume, firstTxn, lastTxn, bName, bLast4, t, client.id]
        );
      } else {
        // Insert new client
        await DB.run(
          `INSERT INTO clients (
             cnic, full_name, phone, whatsapp, bank_name, bank_account, bank_last4,
             is_verified, is_flagged, flag_reason,
             total_txns, total_volume_pkr, first_txn_date, last_txn_date,
             notes, created_at, updated_at
           ) VALUES (?, ?, '', '', ?, '', ?, 0, 0, '', 1, ?, ?, ?, '', ?, ?)`,
          [
            cnic || null,
            name || 'Unknown',
            record.bank_name || '',
            record.bank_last4 || '',
            amount,
            t,
            t,
            t,
            t
          ]
        );
      }
    },

    async verifyRecord(txn) {
  // Use the version-aware builder — v1 records verify under the v1
  // field order; v2 (and future) records use their own order.

  // ── SEC-FIX 6: Salt selection ────────────────────────────────────────
  //
  // No per-record migration marker exists in the schema that reliably
  // identifies which salt was active at insert time (app_settings rows
  // are destroyed by resetAppConfigOnly(), so chain_salt.updated_at
  // cannot be trusted across all installs).
  //
  // Strategy:
  //   1. DEMS-v1 records are definitively pre-SEC-FIX-6 — skip directly
  //      to SALT_LEGACY, saving one SHA-256 call per legacy record.
  //   2. DEMS-v2+ records try the current install salt first (the fast
  //      path for all post-migration records), then fall back to
  //      SALT_LEGACY only on mismatch (handles pre-migration v2 records
  //      that existed before setup wrote a custom chain_salt).
  //   3. Report tampered only if both attempts fail.
  //
  // The fallback is safe: SALT_LEGACY is already in this source file,
  // so a dual-trial adds no new capability to an attacker. SHA-256
  // pre-image resistance ensures a tampered record cannot be crafted
  // to pass either salt check.
  //
  // legacySalt:true in the result flags a pre-migration record so
  // callers can surface a diagnostic or queue a background re-hash.

  const isV1    = (txn.hash_version || '').trim() === 'DEMS-v1';
  const salt    = await _getSalt();

  // Fast path for definitive pre-migration records (DEMS-v1).
  if (isV1) {
    const payload      = buildHashPayloadV1(txn, txn.prev_hash, SALT_LEGACY);
    const computedHash = await sha256(payload);
    const valid        = computedHash === txn.hash;
    return {
      valid        : valid,
      storedHash   : txn.hash,
      computedHash : computedHash,
      tampered     : !valid,
      legacySalt   : true,
      receiptNumber: txn.receipt_number,
      chainIndex   : txn.chain_index
    };
  }

  // Standard path: try current install salt first (DEMS-v2 and future).
  const payload      = buildHashPayloadForRecord(txn, txn.prev_hash, salt);
  const computedHash = await sha256(payload);

  if (computedHash === txn.hash) {
    return {
      valid        : true,
      storedHash   : txn.hash,
      computedHash : computedHash,
      tampered     : false,
      legacySalt   : false,
      receiptNumber: txn.receipt_number,
      chainIndex   : txn.chain_index
    };
  }

  // Fallback: current salt failed — retry with SALT_LEGACY for v2 records
  // that existed before setup wrote a custom chain_salt to app_settings.
  // Only attempted when the current salt actually differs from SALT_LEGACY
  // (i.e. a custom chain_salt is in use); skipped on pre-migration installs
  // where _getSalt() already returned SALT_LEGACY.
  if (salt !== SALT_LEGACY) {
    const legacyPayload = buildHashPayloadForRecord(txn, txn.prev_hash, SALT_LEGACY);
    const legacyHash    = await sha256(legacyPayload);

    if (legacyHash === txn.hash) {
      return {
        valid        : true,
        storedHash   : txn.hash,
        computedHash : legacyHash,
        tampered     : false,
        legacySalt   : true,
        receiptNumber: txn.receipt_number,
        chainIndex   : txn.chain_index
      };
    }
  }

  // Both salt attempts failed — record is tampered or corrupt.
  return {
    valid        : false,
    storedHash   : txn.hash,
    computedHash : computedHash,
    tampered     : true,
    legacySalt   : false,
    receiptNumber: txn.receipt_number,
    chainIndex   : txn.chain_index
  };
},

    verifyChainLink(txn, prevTxn) {
      const expected = prevTxn ? prevTxn.hash : GENESIS_HASH;
      const actual   = txn.prev_hash;
      const linked   = expected === actual;

      return {
        linked   : linked,
        expected : expected,
        actual   : actual,
        broken   : !linked
      };
    },

    async verifyChain(onProgress = null) {
      const startTime = Date.now();

      try {
        const transactions = await DB.all(
          `SELECT * FROM transactions ORDER BY chain_index ASC`
        );

        const total   = transactions.length;
        const results = [];
        let   broken  = false;
        let   firstBreakAt = null;

        if (total === 0) {
          return {
            status          : 'EMPTY',
            message         : 'No transactions in chain yet.',
            total           : 0,
            verified        : 0,
            tampered        : 0,
            brokenLinks     : 0,
            chainIntact     : true,
            verificationTime: Date.now() - startTime,
            results         : []
          };
        }

        for (let i = 0; i < total; i++) {
          const txn     = transactions[i];
          const prevTxn = i > 0 ? transactions[i - 1] : null;

          const hashCheck = await this.verifyRecord(txn);
          const linkCheck = this.verifyChainLink(txn, prevTxn);
          const recordOk = hashCheck.valid && linkCheck.linked;

          if (!recordOk && !broken) {
            broken       = true;
            firstBreakAt = txn.chain_index;
          }

          results.push({
            chainIndex    : txn.chain_index,
            receiptNumber : txn.receipt_number,
            timestamp     : txn.timestamp,
            hashValid     : hashCheck.valid,
            linkValid     : linkCheck.linked,
            intact        : recordOk,
            storedHash    : txn.hash.substring(0, 16) + '…',
            computedHash  : hashCheck.computedHash.substring(0, 16) + '…'
          });

          if (onProgress) {
            onProgress(i + 1, total, Math.round(((i + 1) / total) * 100));
          }
        }

        const tampered    = results.filter(r => !r.intact).length;
        const intact      = results.filter(r =>  r.intact).length;
        const brokenLinks = results.filter(r => !r.linkValid).length;

        const status = tampered === 0 ? 'INTACT' : 'COMPROMISED';

        AuditLog.add(
          'CHAIN_VERIFIED',
          `Status: ${status} | Total: ${total} | Tampered: ${tampered} | Time: ${Date.now() - startTime}ms`
        );

        return {
          status          : status,
          message         : tampered === 0
            ? `All ${total} transactions verified. Chain is intact.`
            : `WARNING: ${tampered} tampered record(s) detected. First breach at chain index #${firstBreakAt}.`,
          total           : total,
          verified        : intact,
          tampered        : tampered,
          brokenLinks     : brokenLinks,
          chainIntact     : tampered === 0,
          firstBreakAt    : firstBreakAt,
          verificationTime: Date.now() - startTime,
          results         : results
        };

      } catch (e) {
        console.error('[HashEngine] verifyChain error:', e);
        AuditLog.add('CHAIN_VERIFY_ERROR', e.message);
        return {
          status      : 'ERROR',
          message     : 'Chain verification failed: ' + e.message,
          chainIntact : false,
          error       : e.message
        };
      }
    },

    async verifyByReceiptNumber(receiptNumber) {
      try {
        const txn = await DB.get(
          `SELECT * FROM transactions WHERE receipt_number = ?`,
          [receiptNumber]
        );

        if (!txn) {
          await logVerification(receiptNumber, 'NOT_FOUND');
          return {
            found         : false,
            status        : 'NOT_FOUND',
            receiptNumber : receiptNumber,
            message       : 'No transaction found with this receipt number.'
          };
        }

        const hashCheck = await this.verifyRecord(txn);

        let prevTxn = null;
        if (txn.chain_index > 0) {
          prevTxn = await DB.get(
            `SELECT * FROM transactions WHERE chain_index = ?`,
            [txn.chain_index - 1]
          );
        }
        const linkCheck = this.verifyChainLink(txn, prevTxn);

        const overallIntact = hashCheck.valid && linkCheck.linked;

        AuditLog.add(
          'RECEIPT_VERIFIED',
          `Receipt: ${receiptNumber} | Result: ${overallIntact ? 'ORIGINAL' : 'TAMPERED'}`
        );
        await logVerification(txn.receipt_number, overallIntact ? 'ORIGINAL' : 'TAMPERED');

        return {
          found         : true,
          status        : overallIntact ? 'ORIGINAL' : 'TAMPERED',
          receiptNumber : txn.receipt_number,
          chainIndex    : txn.chain_index,
          timestamp     : txn.timestamp,
          txnType       : txn.txn_type,
          amountPkr     : txn.amount_pkr,
          clientName    : txn.client_name,
          hashValid     : hashCheck.valid,
          linkValid     : linkCheck.linked,
          intact        : overallIntact,
          storedHash    : txn.hash,
          computedHash  : hashCheck.computedHash,
          message       : overallIntact
            ? 'This is a verified ORIGINAL document. It has not been tampered with.'
            : 'WARNING: This document has been TAMPERED. Data may have been modified.'
        };

      } catch (e) {
        console.error('[HashEngine] verifyByReceiptNumber error:', e);
        return {
          found   : false,
          status  : 'ERROR',
          message : 'Verification error: ' + e.message
        };
      }
    },

    async verifyByHash(hash) {
      try {
        const cleanHash = (hash || '').trim().toLowerCase();

        const txn = await DB.get(
          `SELECT * FROM transactions WHERE hash = ?`,
          [cleanHash]
        );

        if (!txn) {
          await logVerification('', 'NOT_FOUND');
          return {
            found   : false,
            status  : 'NOT_FOUND',
            hash    : cleanHash,
            message : 'No transaction found with this hash.'
          };
        }

        const hashCheck = await this.verifyRecord(txn);

        let prevTxn = null;
        if (txn.chain_index > 0) {
          prevTxn = await DB.get(
            `SELECT * FROM transactions WHERE chain_index = ?`,
            [txn.chain_index - 1]
          );
        }
        const linkCheck = this.verifyChainLink(txn, prevTxn);

        const overallIntact = hashCheck.valid && linkCheck.linked;

        AuditLog.add(
          'HASH_VERIFIED',
          `Hash: ${this.formatHashShort(cleanHash)} | Result: ${overallIntact ? 'ORIGINAL' : 'TAMPERED'}`
        );
        await logVerification(txn.receipt_number, overallIntact ? 'ORIGINAL' : 'TAMPERED');

        return {
          found         : true,
          status        : overallIntact ? 'ORIGINAL' : 'TAMPERED',
          receiptNumber : txn.receipt_number,
          chainIndex    : txn.chain_index,
          timestamp     : txn.timestamp,
          txnType       : txn.txn_type,
          amountPkr     : txn.amount_pkr,
          clientName    : txn.client_name,
          hashValid     : hashCheck.valid,
          linkValid     : linkCheck.linked,
          intact        : overallIntact,
          storedHash    : txn.hash,
          computedHash  : hashCheck.computedHash,
          message       : overallIntact
            ? 'This is a verified ORIGINAL document. It has not been tampered with.'
            : 'WARNING: This document has been TAMPERED. Data may have been modified.'
        };

      } catch (e) {
        console.error('[HashEngine] verifyByHash error:', e);
        return {
          found   : false,
          status  : 'ERROR',
          message : 'Verification error: ' + e.message
        };
      }
    },

    async startupCheck() {
      try {
        const total = await DB.get(
          `SELECT COUNT(*) as cnt, MAX(chain_index) as maxIdx FROM transactions`
        );

        if (!total || total.cnt === 0) {
          return { ok: true, status: 'EMPTY', message: 'No transactions yet.', count: 0 };
        }

        const tip = await DB.get(
          `SELECT * FROM transactions ORDER BY chain_index DESC LIMIT 1`
        );

        const tipCheck = await this.verifyRecord(tip);
        const expectedCount = tip.chain_index + 1;
        const countMismatch = total.cnt !== expectedCount;

        const ok = tipCheck.valid && !countMismatch;

        AuditLog.add(
          'STARTUP_CHECK',
          `Status: ${ok ? 'OK' : 'ALERT'} | Chain tip: #${tip.chain_index} | Count: ${total.cnt} | Tip hash: ${tipCheck.valid ? 'valid' : 'INVALID'}`
        );

        if (!ok) {
          return {
            ok      : false,
            status  : 'ALERT',
            message : countMismatch
              ? `Chain count mismatch: ${total.cnt} records found but sequence expects ${expectedCount}. Records may have been deleted.`
              : `Chain tip hash is invalid. Last record (${tip.receipt_number}) may have been tampered.`,
            count   : total.cnt,
            tipReceipt: tip.receipt_number
          };
        }

        return {
          ok         : true,
          status     : 'OK',
          message    : `Chain OK — ${total.cnt} records verified at tip.`,
          count      : total.cnt,
          tipReceipt : tip.receipt_number
        };

      } catch (e) {
        console.error('[HashEngine] startupCheck error:', e);
        return { ok: false, status: 'ERROR', message: e.message };
      }
    },

    async computeHash(input) {
      return await sha256(input);
    },

    getGenesisHash() {
      return GENESIS_HASH;
    },

    formatHashShort(hash) {
      if (!hash || hash.length < 16) return hash;
      return `${hash.substring(0, 8)}…${hash.substring(hash.length - 8)}`;
    },

    validateFormData(formData) {
      if (!formData.txn_type || !['buy', 'sell'].includes(formData.txn_type)) {
        return { valid: false, error: 'Transaction type must be "buy" or "sell".' };
      }
      const amount = parseFloat(formData.amount_pkr);
      if (!amount || amount <= 0) {
        return { valid: false, error: 'Amount PKR must be a positive number.' };
      }
      const rate = parseFloat(formData.exchange_rate);
      if (!rate || rate <= 0) {
        return { valid: false, error: 'Exchange rate must be a positive number.' };
      }

      // ── Optional profit-tracking fields ─────────────────────────────────
      // cost_rate: must be a positive finite number when provided.
      //   A rate of zero makes no financial sense; negative rates are invalid.
      const costRateRaw = formData.cost_rate;
      if (costRateRaw !== '' && costRateRaw != null) {
        const costRate = parseFloat(costRateRaw);
        if (isNaN(costRate) || !isFinite(costRate)) {
          return { valid: false, error: 'Cost / Market Rate must be a valid number when provided.' };
        }
        if (costRate <= 0) {
          return { valid: false, error: 'Cost / Market Rate must be greater than zero when provided.' };
        }
      }

      // profit_pkr: any finite number is valid — negative values represent
      // a confirmed loss and must not be rejected by validation.
      const profitPkrRaw = formData.profit_pkr;
      if (profitPkrRaw !== '' && profitPkrRaw != null) {
        const profitPkr = parseFloat(profitPkrRaw);
        if (isNaN(profitPkr) || !isFinite(profitPkr)) {
          return { valid: false, error: 'Profit / Loss (PKR) must be a valid number when provided.' };
        }
      }

      // COMPLIANCE-FIX 3 — CNIC format validation (data-layer guard).
      // Enforces the Pakistani CNIC format XXXXX-XXXXXXX-X at the engine
      // level so no malformed CNIC can ever reach the hash payload or DB,
      // regardless of which UI path submitted the record.
      if (formData.client_cnic && formData.client_cnic.trim()) {
        const cnic = formData.client_cnic.trim();
        if (!/^\d{5}-\d{7}-\d$/.test(cnic)) {
          return { valid: false, error: 'CNIC format must be XXXXX-XXXXXXX-X (e.g. 42201-1234567-8).' };
        }
      }

      return { valid: true };
    },

    async getChainSummary() {
      try {
        const row = await DB.get(
          `SELECT
             COUNT(*)             as total,
             MAX(chain_index)     as tip_index,
             MIN(timestamp)       as first_txn,
             MAX(timestamp)       as last_txn,
             SUM(amount_pkr)      as total_volume,
             SUM(CASE WHEN clock_unverified = 1 THEN 1 ELSE 0 END) as clock_unverified_count
           FROM transactions`
        );
        const tip = await DB.get(
          `SELECT hash, receipt_number FROM transactions ORDER BY chain_index DESC LIMIT 1`
        );
        return {
          total       : row?.total       || 0,
          tipIndex    : row?.tip_index   ?? -1,
          firstTxn    : row?.first_txn   || null,
          lastTxn     : row?.last_txn    || null,
          totalVolume : row?.total_volume || 0,
          tipHash     : tip?.hash        || GENESIS_HASH,
          tipReceipt  : tip?.receipt_number || null,
          clockUnverifiedCount : row?.clock_unverified_count || 0
        };
      } catch {
        return { total: 0, tipIndex: -1, tipHash: GENESIS_HASH, clockUnverifiedCount: 0 };
      }
    },

    /**
     * getClockUnverifiedReport()
     * Lists transactions where the device clock could not be confirmed
     * against network time at submission (clock_unverified = 1), for
     * surfacing in chain-integrity / reports views. Does not affect hash
     * or chain-link verification — this is a transparency signal only.
     */
    async getClockUnverifiedReport() {
      try {
        const rows = await DB.all(
          `SELECT chain_index, receipt_number, timestamp, txn_type, amount_pkr
           FROM transactions
           WHERE clock_unverified = 1
           ORDER BY chain_index ASC`
        );
        return {
          count   : rows.length,
          records : rows
        };
      } catch (e) {
        console.error('[HashEngine] getClockUnverifiedReport error:', e);
        return { count: 0, records: [] };
      }
    },

    // ════════════════════════════════════════════════════════
    //  TAMPER-EVIDENCE ANCHORING
    //  (additive — does not alter the hash chain logic above)
    //
    //  IMPORTANT SCOPE NOTE: everything above this point proves
    //  INTERNAL CONSISTENCY ONLY — that each record's hash matches
    //  its own data, and that each record correctly links to the
    //  previous one. It cannot detect a rewrite where someone with
    //  access to this device edits a record AND recomputes every
    //  hash/link from that point forward to match — that produces
    //  a chain that is perfectly "intact" by the checks above, yet
    //  was altered. An anchor is a snapshot of the chain tip taken
    //  at a point in time and saved OUTSIDE this device (emailed,
    //  printed, uploaded elsewhere). Comparing a later chain state
    //  against an old anchor is what can catch that kind of rewrite,
    //  because the attacker cannot also go back and edit the copy
    //  you already moved off the device.
    // ════════════════════════════════════════════════════════

    ANCHOR_LS_KEY: 'dems_last_anchor_meta',

    /**
     * Builds a small, human-and-machine-readable anchor snapshot of the
     * current chain tip: tip index, tip hash, total record count, and the
     * time it was taken. This is NOT the full chain — just enough to later
     * detect if the chain has been silently rewritten up to that point.
     */
    async exportChainAnchor() {
      try {
        const summary = await this.getChainSummary();

        if (summary.total === 0) {
          return {
            success: false,
            error: 'Chain is empty — nothing to anchor yet.'
          };
        }

        const anchor = {
          anchor_version : 'DEMS-ANCHOR-v1',
          created_at     : new Date().toISOString(),
          tip_index      : summary.tipIndex,
          tip_hash       : summary.tipHash,
          tip_receipt    : summary.tipReceipt,
          record_count   : summary.total
        };

        // Sign the anchor itself so the anchor FILE can't be silently
        // hand-edited after the fact without detection either.
        const anchorPayload = [
          anchor.anchor_version,
          anchor.created_at,
          String(anchor.tip_index),
          anchor.tip_hash,
          anchor.tip_receipt || '',
          String(anchor.record_count),
          await _getSalt()
        ].join('|');
        anchor.anchor_signature = await sha256(anchorPayload);

        // Remember locally that an anchor was taken, so the dashboard can
        // remind the user if it's been too long since the last one.
        try {
          localStorage.setItem(this.ANCHOR_LS_KEY, JSON.stringify({
            takenAt  : anchor.created_at,
            tipIndex : anchor.tip_index,
            tipHash  : anchor.tip_hash
          }));
        } catch (e) { /* localStorage unavailable — non-fatal */ }

        AuditLog.add(
          'CHAIN_ANCHOR_EXPORTED',
          `Tip: #${anchor.tip_index} (${anchor.tip_receipt || '—'}) | Records: ${anchor.record_count}`
        );

        return { success: true, anchor: anchor };

      } catch (e) {
        console.error('[HashEngine] exportChainAnchor error:', e);
        return { success: false, error: e.message };
      }
    },

    /**
     * Checks whether an anchor file is internally well-formed and signed
     * correctly (i.e. hasn't itself been hand-edited since export).
     */
    async _verifyAnchorSignature(anchor) {
      if (!anchor || !anchor.anchor_version || !anchor.anchor_signature) {
        return false;
      }
      const payload = [
        anchor.anchor_version,
        anchor.created_at,
        String(anchor.tip_index),
        anchor.tip_hash,
        anchor.tip_receipt || '',
        String(anchor.record_count),
        await _getSalt()
      ].join('|');
      const expected = await sha256(payload);
      return expected === anchor.anchor_signature;
    },

    /**
     * Compares a previously saved anchor against the CURRENT chain state.
     * Three distinct outcomes are possible:
     *   - MATCH: the record that was at the anchor's tip index still has
     *     exactly the hash the anchor recorded. Nothing covered by this
     *     anchor has been altered.
     *   - MISMATCH: a record exists at that index but its hash differs,
     *     or that part of the chain is missing entirely. This means
     *     something covered by the anchor changed after the anchor was
     *     taken — the strongest signal of off-device-undetectable
     *     tampering this app can give you.
     *   - ANCHOR_INVALID: the anchor file itself fails its own signature
     *     check, so it can't be trusted as a reference point at all.
     */
    async verifyAgainstAnchor(anchor) {
      try {
        const sigOk = await this._verifyAnchorSignature(anchor);
        if (!sigOk) {
          return {
            status  : 'ANCHOR_INVALID',
            message : 'This anchor file failed its own signature check — it may be corrupted or hand-edited, and cannot be used as a trusted reference point.'
          };
        }

        const recordAtAnchor = await DB.get(
          `SELECT * FROM transactions WHERE chain_index = ?`,
          [anchor.tip_index]
        );

        if (!recordAtAnchor) {
          return {
            status     : 'MISMATCH',
            message    : `No record exists at chain index #${anchor.tip_index} anymore. The chain has changed since this anchor (${anchor.created_at}) was taken — possibly records were deleted.`,
            anchor     : anchor,
            currentTip : (await this.getChainSummary()).tipIndex
          };
        }

        const matches = recordAtAnchor.hash === anchor.tip_hash;

        AuditLog.add(
          'CHAIN_ANCHOR_VERIFIED',
          `Anchor tip #${anchor.tip_index} (${anchor.created_at}) | Result: ${matches ? 'MATCH' : 'MISMATCH'}`
        );

        if (!matches) {
          return {
            status  : 'MISMATCH',
            message : `Record at chain index #${anchor.tip_index} no longer matches the hash saved in this anchor from ${anchor.created_at}. Data covered by this anchor was altered after it was taken.`,
            anchor  : anchor,
            anchorHash  : anchor.tip_hash,
            currentHash : recordAtAnchor.hash
          };
        }

        return {
          status  : 'MATCH',
          message : `Chain index #${anchor.tip_index} still matches the hash recorded in this anchor from ${anchor.created_at}. Everything up to that point is consistent with what was anchored.`,
          anchor  : anchor
        };

      } catch (e) {
        console.error('[HashEngine] verifyAgainstAnchor error:', e);
        return { status: 'ERROR', message: 'Anchor verification error: ' + e.message };
      }
    },

    /**
     * Returns metadata about the last anchor taken on this device (if any),
     * and whether it's overdue (>24h old), for dashboard reminder UI.
     */
    getLastAnchorMeta() {
      try {
        const raw = localStorage.getItem(this.ANCHOR_LS_KEY);
        if (!raw) return { hasAnchor: false, overdue: true };

        const meta = JSON.parse(raw);
        const ageMs = Date.now() - new Date(meta.takenAt).getTime();
        const overdue = ageMs > 24 * 60 * 60 * 1000;

        return {
          hasAnchor : true,
          takenAt   : meta.takenAt,
          tipIndex  : meta.tipIndex,
          overdue   : overdue
        };
      } catch (e) {
        return { hasAnchor: false, overdue: true };
      }
    },

    // ════════════════════════════════════════════════════════
    //  VOID / CORRECTION WORKFLOW
    //
    //  Design invariants:
    //   1. The original transaction is NEVER modified or deleted.
    //   2. The correction entry is a full, independent chain member:
    //      it gets its own chain_index, prev_hash, hash, receipt_number.
    //   3. is_void = 1 on the correction entry flags it as a void record.
    //   4. voids_chain_index on the correction entry points at the original.
    //   5. A void entry can never itself be voided (guard in voidTransaction).
    //   6. Void entries participate normally in chain verification — the
    //      chain-integrity checker does not skip them.
    // ════════════════════════════════════════════════════════

    /**
     * voidTransaction(originalChainIndex, voidReason)
     *
     * Creates a new correction-entry transaction that records the void.
     * Does NOT modify, update, or delete the original row — ever.
     *
     * Returns { success, record, receiptNumber } on success or
     *         { success: false, error } on failure.
     */
    async voidTransaction(originalChainIndex, voidReason) {
      try {
        // ── 1. Load the original ────────────────────────────────────────
        const original = await DB.get(
          `SELECT * FROM transactions WHERE chain_index = ?`,
          [originalChainIndex]
        );
        if (!original) {
          return { success: false, error: `No transaction found at chain index #${originalChainIndex}.` };
        }

        // ── 2. Guard: void entries cannot themselves be voided ──────────
        if (original.is_void) {
          return {
            success: false,
            error: 'Correction entries cannot be voided. Only original transactions can be corrected.'
          };
        }

        // ── 3. Guard: each original can only be voided once ────────────
        const existingVoid = await DB.get(
          `SELECT id FROM transactions WHERE voids_chain_index = ? AND is_void = 1`,
          [originalChainIndex]
        );
        if (existingVoid) {
          return {
            success: false,
            error: `Block #${originalChainIndex} has already been voided. To correct further, void the correction entry or contact your compliance officer.`
          };
        }

        // ── 4. Build the void record ────────────────────────────────────
        const timestamp     = getDeviceTimestamp();
        const receiptNumber = await DB.getNextReceiptNumber();
        const { prevHash, nextIndex } = await getChainState();

        // The correction entry copies the financial fields from the original
        // so a reader can immediately see what was corrected without needing
        // to look up the original separately. All other fields reflect the
        // correction itself (new timestamp, new chain slot, etc.).
        const record = {
          receipt_number  : receiptNumber,
          order_id        : original.order_id        || '',
          txn_type        : original.txn_type,           // same direction as original
          amount_pkr      : original.amount_pkr,
          exchange_rate   : original.exchange_rate,
          amount_usdt     : original.amount_usdt,
          cost_rate       : original.cost_rate    ?? null,
          profit_pkr      : original.profit_pkr   ?? null,
          client_name     : original.client_name    || '',
          client_cnic     : original.client_cnic    || '',
          bank_name       : original.bank_name      || '',
          bank_last4      : original.bank_last4     || '',
          payment_ref     : original.payment_ref    || '',
          notes           : `VOID REASON: ${(voidReason || '').trim()}`,
          screenshot_path : '',
          timestamp       : timestamp,
          chain_index     : nextIndex,
          prev_hash       : prevHash,
          is_locked       : 1,
          clock_unverified: 0,
          hash_version    : HASH_VERSION,
          // Void-specific fields
          is_void             : 1,
          voids_chain_index   : originalChainIndex
        };

        // Hash is computed the same way as any other record (v2 payload).
        // is_void and voids_chain_index are NOT in the hash payload by design:
        // adding them would break backward compatibility of the DEMS-v2 field
        // order. They are stored as metadata columns alongside the hash, not
        // inside the signed payload — which is exactly how is_locked and
        // clock_unverified are also handled.
        const payload = buildHashPayload(record, prevHash, await _getSalt());
        record.hash   = await sha256(payload);

        // ── 5. Insert — no UPDATE or DELETE on transactions, ever ──────
        await DB.run(
          `INSERT INTO transactions (
            receipt_number, order_id, txn_type,
            amount_pkr, exchange_rate, amount_usdt,
            cost_rate, profit_pkr,
            client_name, client_cnic,
            bank_name, bank_last4, payment_ref,
            notes, screenshot_path,
            timestamp, hash, prev_hash, chain_index, is_locked, clock_unverified,
            hash_version, is_void, voids_chain_index
          ) VALUES (
            ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?
          )`,
          [
            record.receipt_number,  record.order_id,        record.txn_type,
            record.amount_pkr,      record.exchange_rate,   record.amount_usdt,
            record.cost_rate,       record.profit_pkr,
            record.client_name,     record.client_cnic,
            record.bank_name,       record.bank_last4,      record.payment_ref,
            record.notes,           record.screenshot_path,
            record.timestamp,       record.hash,            record.prev_hash,
            record.chain_index,     record.is_locked,       record.clock_unverified,
            record.hash_version,    record.is_void,         record.voids_chain_index
          ]
        );

        AuditLog.add(
          'TRANSACTION_VOIDED',
          `Void entry: ${record.receipt_number} (Block #${record.chain_index}) | ` +
          `Voids: Block #${originalChainIndex} (${original.receipt_number}) | ` +
          `Reason: ${(voidReason || '').trim().substring(0, 120)}`
        );

        // Reverse the original transaction's contribution to the client's
        // KYC stats. The void entry itself must never be passed through
        // syncClientForTransaction() — that would record it as a new
        // transaction and double-count the client's volume instead of
        // correcting it.
        await subtractClientVolume(original);

        return {
          success       : true,
          record        : record,
          receiptNumber : record.receipt_number
        };

      } catch (e) {
        console.error('[HashEngine] voidTransaction error:', e);
        AuditLog.add('VOID_ERROR', `Void failed for chain_index #${originalChainIndex}: ${e.message}`);
        return { success: false, error: e.message };
      }
    },

    /**
     * getVoidInfo(chainIndex)
     *
     * Checks whether an original transaction has been voided by a correction
     * entry. Returns:
     *   { voided: true,  voidChainIndex, voidReceiptNumber, voidReason }
     *   { voided: false }
     *
     * Used by receipt.html to conditionally show the "VOIDED" banner and
     * by transactions.html to show the "VOIDED — See Block #X" badge.
     */
    async getVoidInfo(chainIndex) {
      try {
        const row = await DB.get(
          `SELECT chain_index, receipt_number, notes
           FROM transactions
           WHERE voids_chain_index = ? AND is_void = 1
           LIMIT 1`,
          [chainIndex]
        );

        if (!row) return { voided: false };

        // The void reason is stored as "VOID REASON: <text>" in notes.
        const reason = (row.notes || '').replace(/^VOID REASON:\s*/i, '').trim();

        return {
          voided          : true,
          voidChainIndex  : row.chain_index,
          voidReceiptNumber: row.receipt_number,
          voidReason      : reason
        };
      } catch (e) {
        console.error('[HashEngine] getVoidInfo error:', e);
        return { voided: false };
      }
    },

    // SEC-FIX 6: Called by setup-profile after writing a new chain_salt
    // so the cached value is refreshed on first use post-setup.
    invalidateSaltCache() { _invalidateSaltCache(); }

  };

})();