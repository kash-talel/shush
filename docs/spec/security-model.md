# Authentication & Security Model for "shush"

This document evaluates the options for unlocking and protecting passwords in `shush`: relying on the **Windows OS user login**, a **dedicated Master Password**, or a **Hybrid model (Windows Hello + Master Password)**.

---

## 1. Comparing Authentication Approaches

| Evaluation Criteria | 1. Solely Windows / OS Login (DPAPI) | 2. Pure Master Password | 3. Hybrid: Master Password + Windows Hello (Recommended) |
| :--- | :--- | :--- | :--- |
| **Protection against Malware on User Account** | ❌ **Critical Failure**: Any app/malware running as the logged-in user can silently decrypt all data. | ✅ **High**: Decryption impossible without user typing the password into memory. | ✅ **High**: Physical interaction (PIN/Fingerprint) required via Windows secure prompt. |
| **Portability & Backups** | ❌ **Non-portable**: Vault cannot be moved or recovered on a new/reinstalled PC. | ✅ **100% Portable**: Encrypted file can be backed up to USB or transferred anywhere. | ✅ **100% Portable**: Master Password can unlock vault on any machine. |
| **Disaster Recovery** | ❌ If Windows OS corrupts or user profile breaks, data is permanently lost. | ✅ Data can be decrypted on any machine with the master password. | ✅ Master Password serves as permanent fallback recovery. |
| **User Convenience** | ⭐⭐⭐ Frictionless (No password). | ⭐ High friction (Type complex password every unlock). | ⭐⭐⭐ Frictionless for daily use (Fingerprint / PIN) without sacrificing security. |

---

## 2. Why Relying *Solely* on the Windows OS Login is Insecure

If `shush` delegates security entirely to the operating system (e.g. using Windows Data Protection API / DPAPI without a master password), several fatal vulnerabilities emerge:

```
[Attacker Scenario: Malicious Background Process]
    User is logged into Windows
       │
       ├─► User opens browser / games / downloads an app
       │
       └─► Malicious process executes as current user (same Windows token)
             │
             ▼
       Calls Windows DPAPI: CryptUnprotectData()
             │
             ▼
       Result: Instantly extracts all passwords without any user prompt or password!
```

Other critical risks of OS-only security:
1. **No Defense against Physical Borrowing**: If an unlocked laptop is borrowed by a coworker or friend, they can open the app and see everything immediately.
2. **Reinstall / Drive Swap Brick**: DPAPI keys are tied to the local Windows Security Identifier (SID). If Windows is reinstalled, the master keys are destroyed, making the vault permanently unreadable.

---

## 3. Selected Architecture: Master Password + Keyfile + Windows Hello

`shush` implements an **authenticated multi-factor envelope** combining physical isolation with everyday biometric convenience:

```mermaid
flowchart TD
    subgraph Cold Unlock (Full Authentication)
        MP["1. Master Password\n(Something You Know)"]
        KF["2. Keyfile on USB drive\n(Something You Have)"]
        
        KF -->|"SHA-256 Pre-hash"| KFH["Keyfile Digest (32 bytes)"]
        MP & KFH --> Composite["Composite Secret = UTF8(MP) + KFH"]
        Composite --> Argon2["Argon2id (m=64MB, t=3, p=4, Salt)"]
        Argon2 --> MasterKey["Master Encryption Key"]
        MasterKey --> DecryptVault["Decrypt Vault (.shush)"]
    end

    subgraph Warm Session (Daytime Convenience)
        MasterKey -.->|"If Windows Hello Enabled"| WrapKey["Wrap Session Key in Windows CNG"]
        WrapKey --> TPM["TPM 2.0 Hardware Key\n(NCRYPT_USER_PROTECTION_STRONG)"]
        TPM -->|"Physical Fingerprint / PIN"| UnwrapKey["Unwrap Session Key"]
        UnwrapKey --> DecryptVault
    end
```

### 3.1 The Keyfile Specification
1. **Generation**:
   - The user can let `shush` generate a high-entropy keyfile (`vault.key`) containing **256 bits (32 bytes) of CSPRNG cryptographically secure random bytes** or supply an existing arbitrary file (e.g., an image or binary file).
2. **Digest Hashing**:
   - Before feeding into the KDF, the keyfile is hashed using SHA-256: $\text{KFH} = \text{SHA-256}(\text{KeyfileBytes})$.
   - This ensures arbitrary large files cannot cause buffer memory exhaustion, while maintaining full 256-bit entropy.
3. **Composite Secret Derivation**:
   - The Composite Secret is formed as:
     $$\text{CompositeSecret} = \text{UTF-8}(\text{MasterPassword}) \mathbin{\Vert} \text{KFH}$$
   - This Composite Secret is fed directly into **Argon2id** with the vault's unique 32-byte salt.
4. **Physical Isolation**:
   - The app explicitly instructs the user: *"Save this keyfile onto an external USB flash drive or separate drive partition. Never store it in the same folder as your vault file."*
   - Even if an attacker installs a software keylogger and captures the master password, they **cannot** decrypt the vault without the physical USB keyfile.

### 3.2 Windows Hello Session Lifecycle
1. **Cold Unlock**: Vault requires both **Master Password** and **Keyfile**.
2. **Session Persistence**: While `shush` stays running in the system tray, the user can unlock with **Windows Hello (Fingerprint or PIN)**.
3. **Session Eviction**:
   - When the user explicitly clicks "Lock Vault", memory is zeroed.
   - When the app is closed, system restarted, or user logs out of Windows, the session is invalidated.
   - Next cold start requires the Master Password and Keyfile again.

---

## 4. Cryptographic Agility & Curated Cipher Suites

Should `shush` lock users into a single cipher, or allow users to pick their encryption algorithm?

### 4.1 The Security Dilemma: Choice vs. Rigidity
- **Danger of Open-Ended Choice**: Allowing users to choose arbitrary ciphers (e.g. DES, Blowfish, AES-CBC without HMAC) introduces fatal configuration errors, implementation bloat, and **cipher-downgrade attacks**.
- **The Problem with Rigid Monolithic Ciphers**: Security purists and privacy researchers often distrust NIST/government-blessed ciphers (such as AES) and demand modern alternatives like Daniel J. Bernstein's **ChaCha20**.

### 4.2 The "Curated AEAD Suite" Solution
`shush` implements a strictly constrained **Curated AEAD Suite** with mathematical downgrade protection:

1. **AES-256-GCM** *(Default)*:
   - NIST FIPS standard.
   - Hardware-accelerated via CPU AES-NI instructions (sub-millisecond encryption).
2. **XChaCha20-Poly1305** *(The Power-User Alternative)*:
   - 192-bit extended nonce (zero chance of nonce reuse).
   - Entirely immune to CPU cache-timing side-channel attacks.
   - Completely independent of NIST/FIPS standard bodies.

#### Tamper-Proof Downgrade Defense
The chosen `cipher_suite_id` (e.g., `0x01` or `0x02`) is placed in the binary header and authenticated as **Associated Data (AAD)** inside the AEAD tag. If an attacker tampers with the header byte to force `shush` to decrypt with the wrong cipher, AEAD verification fails instantly before any payload processing.

---

## 5. Summary Recommendation for "shush"

1. **Default Mode**: Master Password (Argon2id) for vault creation and disaster recovery.
2. **Seamless Experience**: Windows Hello (Fingerprint/PIN via TPM 2.0 CNG) for instant day-to-day unlocks while the app is running in the background.
3. **Strict Policy**: Never rely on Windows login password alone; an independent cryptographic key is essential to protect user data from local processes and ensure vault portability.
