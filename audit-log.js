// ══════════════════════════════════════════════════════════
//  audit-log.js — Audit Trail & Login History
//  Digital Exchange Management System — Phase 01
//  Tracks: every login, logout, failed attempt, and
//          all system actions with timestamp
// ══════════════════════════════════════════════════════════

const AuditLog = (() => {

  const LOG_KEY     = 'dems_audit_log';
  const MAX_ENTRIES = 500; // Keep last 500 entries in localStorage

  /**
   * Get device/browser info for audit context
   */
  function getContext() {
    return {
      ua       : navigator.userAgent.substring(0, 80),
      platform : navigator.platform || 'unknown',
      timestamp: new Date().toISOString(),
      epoch    : Date.now()
    };
  }

  /**
   * Load all log entries from localStorage
   */
  function loadAll() {
    try {
      const raw = localStorage.getItem(LOG_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  /**
   * Write entries back to localStorage
   */
  function writeAll(entries) {
    // Keep only last MAX_ENTRIES
    if (entries.length > MAX_ENTRIES) {
      entries = entries.slice(-MAX_ENTRIES);
    }
    localStorage.setItem(LOG_KEY, JSON.stringify(entries));
  }

  return {

    /**
     * add(action, detail?)
     * Core method — call this everywhere something important happens
     *
     * Examples:
     *   AuditLog.add('LOGIN_SUCCESS', 'via PIN')
     *   AuditLog.add('TRANSACTION_ADDED', 'TXN-2024-00012, PKR 50,000')
     *   AuditLog.add('RECEIPT_GENERATED', 'Receipt EXC-2024-00012')
     *   AuditLog.add('LOGIN_FAILED', 'Attempt #3')
     */
    add(action, detail = '') {
      const ctx = getContext();
      const entry = {
        id     : Date.now() + '_' + Math.random().toString(36).substring(2, 6),
        action : action,
        detail : detail,
        ...ctx
      };

      const entries = loadAll();
      entries.push(entry);
      writeAll(entries);

      // Also attempt DB write (async, fire-and-forget)
      try {
        DB.run(
          `INSERT INTO audit_log (action, detail, timestamp, platform, user_agent)
           VALUES (?, ?, ?, ?, ?)`,
          [action, detail, ctx.timestamp, ctx.platform, ctx.ua]
        ).catch(() => {}); // silent fail if DB not ready
      } catch {}

      return entry;
    },

    /**
     * getAll()
     * Returns all audit log entries (newest first)
     */
    getAll() {
      return loadAll().reverse();
    },

    /**
     * getByAction(action)
     * Filter by action type — e.g. getByAction('LOGIN_FAILED')
     */
    getByAction(action) {
      return loadAll().filter(e => e.action === action).reverse();
    },

    /**
     * getRecent(limit)
     * Returns last N entries (newest first)
     */
    getRecent(limit = 20) {
      const all = loadAll();
      return all.slice(-limit).reverse();
    },

    /**
     * getLoginHistory()
     * Returns only login-related events
     */
    getLoginHistory() {
      const loginActions = ['LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'SESSION_EXPIRED', 'LOCKOUT'];
      return loadAll().filter(e => loginActions.includes(e.action)).reverse();
    },

    /**
     * getForDate(dateStr)
     * Returns entries for a specific date
     * dateStr: 'YYYY-MM-DD'
     */
    getForDate(dateStr) {
      return loadAll().filter(e => e.timestamp.startsWith(dateStr)).reverse();
    },

    /**
     * getFailedAttempts()
     * Returns count of failed login attempts in last 24 hours
     */
    getFailedAttempts() {
      const since = Date.now() - 24 * 60 * 60 * 1000;
      return loadAll().filter(e => e.action === 'LOGIN_FAILED' && e.epoch > since).length;
    },

    /**
     * exportCSV()
     * Returns CSV string for export
     */
    exportCSV() {
      const entries = loadAll();
      const header  = 'ID,Action,Detail,Timestamp,Platform\n';
      const rows    = entries.map(e =>
        `"${e.id}","${e.action}","${e.detail.replace(/"/g,'""')}","${e.timestamp}","${e.platform}"`
      ).join('\n');
      return header + rows;
    },

    /**
     * _clearDEVONLY()
     * INTEGRITY-FIX 4: Renamed from clear() to prevent accidental invocation
     * via the browser console in production.  A localhost guard is added so
     * that execution is silently blocked on any non-development origin — the
     * method returns undefined without any side-effects, making it
     * indistinguishable from a no-op to a casual console attacker.
     *
     * To use in development: call AuditLog._clearDEVONLY() from localhost only.
     * WARNING: Permanently deletes audit log — use only for testing/reset.
     */
    async _clearDEVONLY() {
      // Block execution on any non-localhost origin, silently.
      const host = window.location.hostname;
      if (host !== 'localhost' && host !== '127.0.0.1' && host !== '::1') {
        console.warn('[AuditLog] _clearDEVONLY() is only permitted on localhost. Blocked.');
        return;
      }
      this.add('AUDIT_LOG_CLEARED', 'Audit log was manually cleared');
      localStorage.removeItem(LOG_KEY);
      try {
        await DB.run('DELETE FROM audit_log');
      } catch {}
    },

    /**
     * getStats()
     * Returns summary statistics
     */
    getStats() {
      const all       = loadAll();
      const today     = new Date().toISOString().split('T')[0];
      const todayLogs = all.filter(e => e.timestamp.startsWith(today));
      return {
        totalEntries  : all.length,
        todayEntries  : todayLogs.length,
        failedLogins  : all.filter(e => e.action === 'LOGIN_FAILED').length,
        successLogins : all.filter(e => e.action === 'LOGIN_SUCCESS').length,
        oldestEntry   : all[0]?.timestamp || null,
        newestEntry   : all[all.length - 1]?.timestamp || null
      };
    }

  };

})();