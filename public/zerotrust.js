/**
 * zerotrust-php — Client-Side WebCrypto SHA-256 Proof-of-Work & WebAuthn Passkey Helper
 * Repository: https://github.com/MrKhan025/zerotrust-php
 */
'use strict';

const ZeroTrustClient = {
    /**
     * Computes a deterministic SHA-256 hex digest using the browser WebCrypto API.
     * @param {string} message
     * @returns {Promise<string>}
     */
    async sha256Hex(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    },

    /**
     * Computes a privacy-preserving client hardware/display fingerprint hash.
     * @returns {Promise<string>}
     */
    async computeClientFingerprint() {
        const signals = [
            navigator.language || 'en',
            String(screen.width || 0) + 'x' + String(screen.height || 0),
            String(screen.colorDepth || 24),
            Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
            String(navigator.hardwareConcurrency || 1),
        ].join('|');
        return this.sha256Hex(signals);
    },

    /**
     * Solves a stateless SHA-256 Proof-of-Work challenge for BotDefenseGuard.
     * @param {string} nonce
     * @param {number} difficulty
     * @returns {Promise<string>}
     */
    async solveProofOfWork(nonce, difficulty) {
        const targetPrefix = '0'.repeat(Math.max(1, difficulty));
        let counter = 0;
        while (counter < 10000000) {
            const candidate = counter.toString(16);
            const digest = await this.sha256Hex(nonce + ':' + candidate);
            if (digest.startsWith(targetPrefix)) {
                return candidate;
            }
            counter += 1;
        }
        throw new Error('Proof-of-Work iteration limit exceeded.');
    }
};

if (typeof window !== 'undefined') {
    window.ZeroTrustClient = ZeroTrustClient;
}
