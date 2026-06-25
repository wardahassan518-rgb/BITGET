// ══════════════════════════════════════════════════════════
//  auth.js — Authentication & Session Management
//  Digital Exchange Management System
//
//  SEC-FIX 1: Per-credential randomized salts (version 2)
//  SEC-FIX 2: Lockout state stored in SQLite DB (not localStorage)
// ══════════════════════════════════════════════════════════

const Auth = (() => {

  const CREDS_KEY   = 'dems_credentials';
  const SESSION_KEY = 'dems_session';
  const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 hours

  const MAX_ATTEMPTS     = 5;
  const LOCKOUT_DURATION = 5 * 60 * 1000; // 5 minutes in ms

  // ── HASHING ─────────────────────────────────────────────
  //
  // SEC-FIX 1: hashValue now accepts an optional saltHex parameter.
  //   • NEW records (no saltHex): generates a fresh random 16-byte salt.
  //   • VERIFY paths (saltHex provided): reuses the stored salt so the
  //     output is deterministic for comparison.
  //
  // Returns { hash: string, saltHex: string } so callers can store both.
  //
  // Legacy single-arg path used the global suffix '_DEMS_SALT_2024'
  // (version 1 credentials). That path is preserved only in the migration
  // helper _hashLegacy() below — never used for new credentials.
  async function hashValue(value, saltHex) {
    const salt = saltHex || Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const msgBuffer = new TextEncoder().encode(salt + value);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return { hash, saltHex: salt };
  }

  // Legacy hash function — ONLY used during v1→v2 migration to verify an
  // existing v1 credential before re-hashing it with a new random salt.
  async function _hashLegacy(value) {
    const encoded = new TextEncoder().encode(value + '_DEMS_SALT_2024');
    const buffer  = await crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function _loadCreds() {
    try {
      const raw = localStorage.getItem(CREDS_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }

  function _saveCreds(creds) {
    localStorage.setItem(CREDS_KEY, JSON.stringify(creds));
  }

  // ── DB-BACKED LOCKOUT HELPERS (SEC-FIX 2) ───────────────
  //
  // All lockout state lives in the login_lockout table (id=1 row, singleton).
  // localStorage keys 'failedAttempts' and 'lockoutUntil' are no longer
  // used by this module; they remain in localStorage only as dead keys that
  // existing browser data may have — they are ignored going forward.

  async function _getLockoutRow() {
    try {
      return await DB.get('SELECT * FROM login_lockout WHERE id = 1');
    } catch (e) {
      console.warn('[Auth] lockout row unavailable:', e.message);
      return null;
    }
  }

  async function _saveLockoutRow(failedCount, lockoutUntil) {
    const now = new Date().toISOString();
    try {
      await DB.run(
        `INSERT OR REPLACE INTO login_lockout (id, failed_count, lockout_until, updated_at)
         VALUES (1, ?, ?, ?)`,
        [failedCount, lockoutUntil || null, now]
      );
    } catch (e) {
      console.warn('[Auth] lockout row write failed:', e.message);
    }
  }

  return {

    // ── SETUP ──────────────────────────────────────────────
    //
    // SEC-FIX 1: Generates independent random salts for PIN and password.
    // Stores version:2 so login() knows to use the per-cred salt path.
    async setupCredentials(pin, password) {
      const pinResult = await hashValue(pin);
      const pwResult  = await hashValue(password);
      _saveCreds({
        pinHash  : pinResult.hash,
        pinSalt  : pinResult.saltHex,
        pwHash   : pwResult.hash,
        pwSalt   : pwResult.saltHex,
        createdAt: new Date().toISOString(),
        version  : 2
      });
    },

    // ── LOGIN ──────────────────────────────────────────────
    //
    // 1. Checks DB-backed lockout (SEC-FIX 2).
    // 2. Detects v1 credentials and migrates them on first successful login.
    // 3. On failure, increments DB counter and sets lockout if threshold reached.
    async login(credential, type = 'pin') {
      const creds = _loadCreds();
      if (!creds) return { success: false, error: 'No credentials set up.' };

      // ── Migration guard (SEC-FIX 1) ──
      // v1 credentials used a global static salt suffix; they must be
      // verified with the legacy path, then immediately re-hashed with a
      // new random salt and saved as v2 so the account is upgraded.
      const isV1 = !creds.version || creds.version === 1;

      let match = false;

      if (isV1) {
        // Legacy verification
        const legacyHash = await _hashLegacy(credential);
        if (type === 'pin') {
          match = legacyHash === creds.pinHash;
        } else {
          match = legacyHash === creds.pwHash;
        }

        if (match) {
          // Upgrade: re-hash both credentials with new random salts.
          // We only have the current credential in hand right now; the
          // other credential stays as its legacy hash until the user logs
          // in with it (lazy migration). We mark the version as 2 and keep
          // the other hash as-is with a sentinel salt so login() can detect
          // the still-unupgraded credential and fall back to the legacy path.
          const upgraded = await hashValue(credential);
          const newCreds = {
            pinHash  : type === 'pin' ? upgraded.hash : creds.pinHash,
            pinSalt  : type === 'pin' ? upgraded.saltHex : (creds.pinSalt || '__legacy__'),
            pwHash   : type === 'password' ? upgraded.hash : creds.pwHash,
            pwSalt   : type === 'password' ? upgraded.saltHex : (creds.pwSalt || '__legacy__'),
            createdAt: creds.createdAt,
            version  : 2
          };
          _saveCreds(newCreds);
          console.info('[Auth] v1 credential migrated to v2 (randomized salt).');
        }
      } else {
        // v2 path: use the stored per-credential salt.
        // If salt is '__legacy__' the credential has not been upgraded yet
        // (e.g. the other credential type was used at initial migration).
        // Fall back to the legacy hash check for that specific one.
        if (type === 'pin') {
          if (creds.pinSalt === '__legacy__') {
            const legacyHash = await _hashLegacy(credential);
            match = legacyHash === creds.pinHash;
            if (match) {
              const upgraded = await hashValue(credential);
              creds.pinHash = upgraded.hash;
              creds.pinSalt = upgraded.saltHex;
              _saveCreds(creds);
            }
          } else {
            const result = await hashValue(credential, creds.pinSalt);
            match = result.hash === creds.pinHash;
          }
        } else {
          if (creds.pwSalt === '__legacy__') {
            const legacyHash = await _hashLegacy(credential);
            match = legacyHash === creds.pwHash;
            if (match) {
              const upgraded = await hashValue(credential);
              creds.pwHash = upgraded.hash;
              creds.pwSalt = upgraded.saltHex;
              _saveCreds(creds);
            }
          } else {
            const result = await hashValue(credential, creds.pwSalt);
            match = result.hash === creds.pwHash;
          }
        }
      }

      if (match) {
        // Clear lockout state on successful login (SEC-FIX 2)
        await this.clearLockout();
        // Issue session
        const session = {
          loggedIn : true,
          loginAt  : new Date().toISOString(),
          expiresAt: Date.now() + SESSION_DURATION_MS
        };
        localStorage.setItem(SESSION_KEY, JSON.stringify(session));
        return { success: true };
      }

      return { success: false };
    },

    // ── LOCKOUT (SEC-FIX 2) ────────────────────────────────

    /**
     * recordFailedAttempt()
     * Increments the DB failed-attempt counter. If MAX_ATTEMPTS is reached,
     * sets lockout_until to now + LOCKOUT_DURATION.
     * Returns { locked: bool, failedCount: int, lockoutUntil: string|null }
     */
    async recordFailedAttempt() {
      const row = await _getLockoutRow();
      const prevCount = row ? (row.failed_count || 0) : 0;
      const newCount  = prevCount + 1;
      let lockoutUntil = null;

      if (newCount >= MAX_ATTEMPTS) {
        lockoutUntil = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
      }

      await _saveLockoutRow(newCount, lockoutUntil);
      return {
        locked      : !!lockoutUntil,
        failedCount : newCount,
        lockoutUntil: lockoutUntil
      };
    },

    /**
     * getLockoutState()
     * Returns { locked: bool, until: timestamp_ms|null, failedCount: int }
     * "locked" is true only if lockout_until is in the future.
     */
    async getLockoutState() {
      const row = await _getLockoutRow();
      if (!row) return { locked: false, until: null, failedCount: 0 };

      const failedCount = row.failed_count || 0;
      const until = row.lockout_until ? new Date(row.lockout_until).getTime() : null;
      const locked = until ? Date.now() < until : false;

      // Auto-clear expired lockout from DB
      if (until && !locked) {
        await _saveLockoutRow(0, null);
        return { locked: false, until: null, failedCount: 0 };
      }

      return { locked, until: locked ? until : null, failedCount };
    },

    /**
     * clearLockout()
     * Resets the DB counter to 0 (called on successful login).
     */
    async clearLockout() {
      await _saveLockoutRow(0, null);
      // Also clear legacy localStorage keys so old UI doesn't show stale state
      try {
        localStorage.removeItem('failedAttempts');
        localStorage.removeItem('lockoutUntil');
      } catch {}
    },

    // ── SESSION ────────────────────────────────────────────

    checkSession() {
      try {
        const raw = localStorage.getItem(SESSION_KEY);
        if (!raw) return null;
        const s = JSON.parse(raw);
        if (!s.loggedIn || Date.now() >= s.expiresAt) {
          this.logout();
          return null;
        }
        return s;
      } catch { return null; }
    },

    requireAuth() {
      if (!this.checkSession()) {
        window.location.href = 'login.html';
        return false;
      }
      return true;
    },

    logout() {
      localStorage.removeItem(SESSION_KEY);
      window.location.href = 'login.html';
    },

    // ── CREDENTIAL MANAGEMENT ─────────────────────────────

    async changePin(currentPin, newPin) {
      const creds = _loadCreds();
      if (!creds) return false;

      // Verify current PIN using the appropriate path
      let match = false;
      if (!creds.version || creds.version === 1 || creds.pinSalt === '__legacy__') {
        const legacyHash = await _hashLegacy(currentPin);
        match = legacyHash === creds.pinHash;
      } else {
        const result = await hashValue(currentPin, creds.pinSalt);
        match = result.hash === creds.pinHash;
      }

      if (!match) return false;

      const upgraded = await hashValue(newPin);
      creds.pinHash = upgraded.hash;
      creds.pinSalt = upgraded.saltHex;
      creds.version = 2;
      _saveCreds(creds);
      return true;
    },

    async changePassword(currentPin, newPassword) {
      // Verify current PIN first, then update password.
      // NOTE: do NOT call this.changePin() here — changePin() saves a new PIN
      // hash as a side-effect and would corrupt the stored PIN credential.
      const creds = _loadCreds();
      if (!creds) return false;

      let pinMatch = false;
      if (!creds.version || creds.version === 1 || creds.pinSalt === '__legacy__') {
        const legacyHash = await _hashLegacy(currentPin);
        pinMatch = legacyHash === creds.pinHash;
      } else {
        const result = await hashValue(currentPin, creds.pinSalt);
        pinMatch = result.hash === creds.pinHash;
      }

      if (!pinMatch) return false;

      const upgraded = await hashValue(newPassword);
      creds.pwHash = upgraded.hash;
      creds.pwSalt = upgraded.saltHex;
      creds.version = 2;
      _saveCreds(creds);
      return true;
    },

    getCredentialVersion() {
      const creds = _loadCreds();
      return creds?.version || 1;
    }

  };

})();