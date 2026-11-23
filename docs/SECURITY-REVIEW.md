# Security review summary

This document summarises the internal security reviews of Sigillum Arcanum up to version 11.2 (November 2026).
They are **not** an independent external audit.

## Method

Each round combined:

* a separate reviewer who had not seen the implementation, with own attack scripts, followed by verification of
  every finding against the code;
* re-computation of all primitives against independent implementations: kyber-py (ML-KEM-1024), dilithium-py
  (ML-DSA-87), own brainpoolP512r1 arithmetic (RFC 5639), own AES-GCM-SIV/POLYVAL (RFC 8452 vectors), argon2-cffi,
  FIPS 202 vectors for SHA-3;
* comparison with the full text of BSI TR-02102-1;
* fuzzing of every parser (identity file, messages, emergency and backup shares, session data, hand mode);
* machine-learning distinguishability tests on ciphertexts (accuracy 48–51 %, i.e. guessing);
* bandit, pip-audit and hash verification of all pinned dependencies.

## Cryptographic design (as checked against BSI TR-02102-1)

| Function | Choice | TR-02102-1 |
| --- | --- | --- |
| Key exchange | ML-KEM-1024 + ECDH brainpoolP512r1, always hybrid, KeyCombine per NIST SP 800-227 | 2.4.3 (Tab. 2.7), 2.3.6, Tab. 2.1 |
| Signatures | ML-DSA-87 (hedged, with context) + ECDSA brainpoolP512r1 / SHA3-512 (low-s), both must verify | 5.3.4, Tab. 5.5, 5.7 |
| Symmetric | AES-256-GCM-SIV, random 96-bit nonce, header bound as AAD | Tab. 3.1/3.2 |
| KDF | HKDF-SHA-512 with distinct labels; Argon2id 1 GiB / 4 passes / 128-bit salt for passwords | B.1, B.1.2 |
| Hash | SHA3-256 / SHA3-512 | Tab. 4.1 |
| Secret sharing | Shamir 2-of-3 over Mersenne prime fields 2^521−1 / 2^1279−1 | chapter 7 |
| Randomness | operating system CSPRNG (`secrets`) | chapter 8 |

Post-quantum view: contact messages are protected by ML-KEM-1024 in addition to ECDH ("harvest now, decrypt later"
resistant); everything symmetric uses 256-bit keys (128 bits against Grover).

## Findings and status

All findings of all rounds are fixed in 11.2. The last two rounds addressed among others:

* passphrase strength counted only list words (repeated words now do not count; a new identity requires an
  app-generated passphrase);
* forward secrecy only per reply round (now one-time receive keys per message);
* obvious app PINs (sequences, dates incl. separators, keypad walks, common words) rejected for new identities;
* synchronisable passkeys (cloud backup flags) rejected as second factor;
* rollback of an older identity file detected on the same computer;
* clipboard cleared of plaintext on lock; self test extended by vectors from independent implementations;
* fixes did not lock out existing identities or partners (regression tests with frozen files from older versions).

## Known limitations (accepted and documented)

* No independent external audit.
* Malware on the running computer, memory images (Python cannot reliably wipe secrets), all factors stolen together.
* Messages to the base key (first message) or the fallback key (5th unanswered message onwards) are not forward secret.
* The app PIN can be brute-forced offline by someone who holds key file, identity file **and** the YubiKey with its
  FIDO PIN, or a memory image while quick unlock is active (Argon2id slows this down).
* Rollback detection works only on the computer that saw the newer file.
* Old copies of the identity file (cloud versions, backups) still contain the keys that were open at that time.
* Hand-mode check value is 20 bits by design.
* The YubiKey path and Windows lock detection were tested with a software emulation; a manual test on Windows with
  real hardware is part of each release.
