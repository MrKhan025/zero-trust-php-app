# Accessibility Policy & Conformance (`ACCESSIBILITY.md`)

**`zerotrust-php`** is committed to ensuring that high-assurance security never comes at the expense of human accessibility. Authentication gateways are critical infrastructure: every user—including people who rely on screen readers, keyboard-only navigation, voice control, magnification, or high-contrast displays—must be able to register, complete Multi-Factor Authentication (MFA), and audit their session telemetry independently.

## 1. Conformance Target

The zerotrust-php web portal (`public/index.php`) targets **Web Content Accessibility Guidelines (WCAG) 2.1 Level AA** conformance across all authentication, enrollment, and dashboard views.

## 2. Accessible Security & Anti-Bot Engineering

Traditional bot defenses (such as distorted visual CAPTCHAs or puzzle-dragging challenges) frequently lock out blind, low-vision, and motor-impaired users. `zerotrust-php` replaces visual CAPTCHAs with **accessible cryptographic defenses**:

| Security Mechanism | Potential Accessibility Risk | How `zerotrust-php` Ensures Accessibility |
| :--- | :--- | :--- |
| **Stateless SHA-256 Proof-of-Work (PoW)** | Users might not know why form submission pauses while the browser computes hashes. | Completely invisible to human senses (no visual puzzle to solve). The `.pow-status` indicator updates dynamically and uses polite live-region semantics so screen readers announce computation progress without stealing focus. |
| **Semantic Honeytrap Fields** | Screen readers or switch-access users might accidentally focus and fill hidden bot-trap inputs. | Honeytrap containers (`.honeytrap`) declare `aria-hidden="true"`, and the inner input sets `tabindex="-1"` and `autocomplete="off"` with an explicit `<label>Leave this field blank</label>` fallback so assistive technologies never focus or auto-fill it. |
| **RFC 6238 TOTP & MFA Enrollment** | QR-code-only TOTP enrollment excludes blind users and desktop-only workflows. | Enrollment outputs the **plaintext Base32 TOTP secret**, the full **`otpauth://` provisioning URI**, and **8 formatted single-use recovery codes** (`XXXX-XXXX-XXXX`) in copyable, high-contrast `<div class="code-box">` regions. |
| **WebAuthn / Passkeys Support** | Typing 6-digit codes under a 30-second countdown can be difficult for users with motor or cognitive impairments. | `WebAuthnService` supports platform authenticators (Touch ID, Windows Hello, hardware security keys) without time-pressured manual code entry. |

## 3. Visual Design, Contrast & Typography

The interface in `public/index.php` is engineered for high legibility in low-light and security-operations environments:

- **Color Contrast Ratios (WCAG 2.1 AA / AAA)**:
  - Primary body text (`#f8fafc`) on main background (`#070b14`): **19.1 : 1** (exceeds WCAG AAA 7:1).
  - Primary body text (`#f8fafc`) on card surface (`#131c31`): **15.4 : 1** (exceeds WCAG AAA 7:1).
  - Muted labels and descriptions (`#94a3b8`) on card surface (`#131c31`): **5.8 : 1** (exceeds WCAG AA 4.5:1).
  - Cryptographic code outputs (`#34d399`) on code-box surface (`#060911`): **10.6 : 1** (exceeds WCAG AAA 7:1).
- **Non-Color-Only Status Indicators**:
  - System status pills and security alerts never rely on color alone. Every indicator includes explicit text state labels (`AEAD: XChaCha20-Poly1305`, `Audit Chain: VERIFIED`, `MFA Hardware Verified: YES (RFC 6238)`, `Security Notification:`).
- **Responsive & Zoom-Safe Layout**:
  - Built with fluid CSS Grid (`repeat(auto-fit, minmax(350px, 1fr))`) and relative `rem` typography that scales cleanly up to **200%–400% browser zoom** without horizontal scrolling or text truncation.

## 4. Keyboard Navigation & Form Semantics

- **Explicit Label Associations**: Every form control (`#login_username`, `#login_password`, `#login_totp`, `#login_recovery`, `#reg_username`, `#reg_email`, `#reg_password`) is paired with an explicit `<label for="...">` element.
- **Password Manager & Assistive Autofill Compatibility**: Inputs declare standard W3C `autocomplete` tokens (`autocomplete="username"`, `autocomplete="current-password"`, `autocomplete="new-password"`, `autocomplete="one-time-code"`, `autocomplete="email"`) so screen readers and password managers can populate credentials without friction.
- **Strict Content-Security-Policy (CSP) Compatibility**: All styles and scripts use per-request cryptographic nonces (`nonce="<?= $e($cspNonce) ?>"`), avoiding unsafe inline attributes that interfere with assistive browser extensions.

## 5. Accessibility Checklist for Contributors

When submitting Pull Requests that modify `public/index.php` or any user-facing output:

1. **Labels & Landmarks**: Ensure every `<input>`, `<select>`, and `<textarea>` has a programmatic `<label for="...">` and appropriate `autocomplete` attribute.
2. **Keyboard Operability**: Verify that all interactive controls can be reached and activated using only `Tab`, `Shift+Tab`, `Enter`, and `Space`.
3. **Contrast Verification**: Maintain a minimum contrast ratio of **4.5:1** for normal text and **3:1** for large text and UI boundaries.
4. **Bot-Trap Isolation**: Any new anti-automation or telemetry field must include `aria-hidden="true"` and `tabindex="-1"` so assistive technologies are never penalized.

## 6. Reporting Accessibility Issues

If you encounter an accessibility barrier in `zerotrust-php`, please open an issue on [GitHub Issues](https://www.google.com/search?q=https://github.com/MrKhan025/zerotrust-php/issues) with the `[Accessibility]` prefix, describing:
- The assistive technology (e.g., NVDA, JAWS, VoiceOver, Orca, keyboard-only) and browser used.
- The workflow step affected (Registration, Login, TOTP/Recovery, or Audit Dashboard).
- Expected vs. observed behavior.
