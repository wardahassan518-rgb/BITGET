// ══════════════════════════════════════════════════════════
//  profile.js — Business Profile Management
//  Digital Exchange Management System — Phase 01
//  Handles: save profile, load profile, update profile
// ══════════════════════════════════════════════════════════

const Profile = (() => {

  const PROFILE_KEY = 'dems_business_profile';

  return {

    /**
     * save(profileData)
     * Saves business profile to localStorage (and DB if available)
     */
    async save(profileData) {
      const data = {
        ...profileData,
        savedAt  : new Date().toISOString(),
        version  : 1
      };
      localStorage.setItem(PROFILE_KEY, JSON.stringify(data));
      try {
        await DB.run(
          `INSERT OR REPLACE INTO app_settings (key, value, updated_at)
           VALUES ('business_profile', ?, ?)`,
          [JSON.stringify(data), new Date().toISOString()]
        );
      } catch (e) {
        console.warn('Profile DB save skipped:', e.message);
      }
      return data;
    },

    /**
     * get()
     * Returns profile object or null if not set up yet
     */
    async get() {
      try {
        const row = await DB.get(
          `SELECT value FROM app_settings WHERE key = 'business_profile'`
        );
        if (row) return JSON.parse(row.value);
      } catch {
        // DB not ready - fall through
      }
      try {
        const raw = localStorage.getItem(PROFILE_KEY);
        return raw ? JSON.parse(raw) : null;
      } catch {
        return null;
      }
    },

    /**
     * update(fields)
     * Partial update — merges fields into existing profile
     */
    async update(fields) {
      const existing = await this.get();
      if (!existing) throw new Error('No profile found to update');
      const updated = {
        ...existing,
        ...fields,
        updatedAt: new Date().toISOString()
      };
      return await this.save(updated);
    },

    /**
     * getReceiptHeader()
     * Returns formatted strings for receipt generation (Phase 04)
     */
    async getReceiptHeader() {
      const p = await this.get();
      if (!p) return null;
      return {
        line1: p.businessName,
        line2: p.address + (p.area ? ', ' + p.area : '') + ', ' + p.city,
        line3: 'Ph: ' + p.phone + (p.whatsapp ? ' | WA: ' + p.whatsapp : ''),
        line4: 'SECP Reg: ' + p.secpNumber + (p.ntnNumber ? ' | NTN: ' + p.ntnNumber : ''),
        footer: p.receiptFooter || 'Thank you for your business.',
        logo  : p.logoEmoji || '⬡'
      };
    },

    /**
     * exists()
     * Quick check — profile setup complete?
     */
    async exists() {
      const p = await this.get();
      return !!(p && p.businessName && p.secpNumber);
    },

    /**
     * clear()
     * WARNING: Removes profile — only for reset/reinstall
     */
    async clear() {
      localStorage.removeItem(PROFILE_KEY);
      try {
        await DB.run(`DELETE FROM app_settings WHERE key = 'business_profile'`);
      } catch {}
      AuditLog.add('PROFILE_CLEARED', 'Business profile was cleared — system reset');
    }

  };

})();
