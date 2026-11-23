# Sigillum Arcanum – Format v3 (app version 11.4, for reviewers)

*Deutsche Fassung: [`FORMAT.md`](FORMAT.md). If the two differ, the German version and the code are authoritative.*

Aligned with BSI TR-02102-1 (version 2026-01). Primitives: AES-256-GCM-SIV (RFC 8452), HKDF-SHA-512 (RFC 5869),
SHA3-256/-512, SHAKE256, Argon2id, ML-KEM-1024 (FIPS 203) + ECDH-brainpoolP512r1 (RFC 5639), ML-DSA-87 “hedged”
(FIPS 204) + ECDSA-brainpoolP512r1 with SHA3-512. Post-quantum algorithms are used exclusively in hybrid form.
`h3(label, x, n)` = first n bytes of SHA3-256(lp(label) | x) (n ≤ 32). Files in formats v1/v2 are rejected.

All multi-byte integers are big-endian. Every file starts with a header of at least 6 bytes ("SA" | version | mode | …);
shorter files are rejected with a clear message (finding R8-N1). `lp(x)` = 4-byte length + x. Text is UTF-8.
Format v3 applies since 11.2; 11.3 only adds the user interface language, 11.4 the Argon2id check value chk.pw (below).

## Key derivation (modes 1 and 3)
```
keyfile  = "SAKEY2\0\0" | 32 random bytes | h3("SIGILLUM-KEYFILE-CHK", preceding 40 bytes, 4)
pw'      = NFC(pw).casefold(), split on whitespace, joined with exactly one space
material = "SIGILLUM-ARCANUM-v3\0" | lp(purpose) | lp(pw') | lp(NFC(pin).strip()) | lp(keyfile_secret32)
           purpose = "shared" (mode 1) | "identity" (mode 3)
key      = Argon2id(material, salt16, ops = 4, mem = 2^30)
```
When reading, only ops = 4, memlog = 30 are accepted.
On creation: passphrase of ≥ 6 DIFFERENT words from the EFF list (77.5 bits; since 11.2 drawn without replacement,
repetitions do not count; a new identity only with a passphrase rolled in the app). App PIN ≥ 6 characters and not
guessable (since 11.2, core.pin_problem: ≤ 2 distinct characters, number/letter/keyboard sequences and number-pad
paths, repetitions with period 2–4, mirror patterns, interleaved patterns, dates with and without separators, common
words including leetspeak; only ASCII digits count as digits; blocks ~17 % of 6-digit numeric codes; TR-02102-1
remark 6.2). Since the PIN can be attacked offline, its protection rests on the possession factors (remark 6.4 (iii)).
The app enforces different key files and passphrases for modes 1 and 3.

## Payload (inner)
```
0x03 | flags(1) | unix_time(8) | msgid(16) | sender(16) | text_length(4) | text | 0x00 padding
```
Padded to 128 · 2^k bytes; padding bytes must be 0. Text ≤ 256 KiB.
sender = channel ID HMAC-SHA256(device secret, "SIGILLUM-CHAN" | key file ID)[0:16] (mode 1)
         or the first 16 bytes of the sender fingerprint (mode 4).

## Mode 1 – shared key
```
header = "SA" | 0x03 | 0x01 | ops | memlog | salt16 | nonce12
blob   = header | AES-256-GCM-SIV(key, nonce, inner, aad = header)         (tag 128 bits)
```

## Mode 3 – identity file
```
header  = "SA" | 0x03 | 0x03 | ops | memlog | salt16 | nonce12
content = "SAPRV5" | lp(name) | kem_seed32 | ecdsa_seed32 | mldsa87_seed32 | lp(state_json)
state   = {"v":4, "book": {fp: {name, pub, verified, method, …}}, "contacts": {fp: key state},
           "sheets": {sheet no.: message ID}, "sheets_opened": {sheet no.: number of decryptions},
           "seen": {fp: {"ids": [h3("SIGILLUM-SEEN", msgid, 16)], "ts": lower bound}}}
           "chk": {"a": hex(h3("SIGILLUM-v11-A-CHECK", A, 32)), "d": hex(h3("SIGILLUM-v11-A2-CHECK", A2, 32)),
                   "pw_salt": hex16, "pwk": [3, 26],
                   "pw": hex(Argon2id("SIGILLUM-ARCANUM-v3\0" | lp("pwcheck") | lp(pw'), pw_salt, ops = 3, mem = 2^26))},
           "partners": {pid16hex: {"name", "kf": hex(keyfile44), "pw": pw', "pin", "created", "last_used"}},
           "recovery_pending"?: bool,
           "gen"?: write generation (11.2, R12-N4; missing = 0; +1 on every save),
           "spent"?: [h3("SIGILLUM-SPENT", header, 16)] (11.2, R12-N1; at most 2000)}
           ("seen" holds at most 2000 IDs per contact and is kept across restarts and when the contact is removed;
           at most 64 partners; every partner entry must satisfy the same rules on loading as on creation:
           valid name, key file, Diceware passphrase of ≥ 6 list words in canonical form, PIN ≥ 6, never the
           identity passphrase (on loading deliberately without the stricter 11.2 rule “no repetition”, so that
           nobody gets locked out); any deviation in the state is rejected – older forms are not migrated)
chk.a     : proves before security-critical changes that passphrase + PIN + key file are correct
            (step-up confirmation), also in an everyday session without passphrase.
chk.d     : check value for A2 (everyday key, purpose "daily"); checked on everyday unlock, in full_keys and
            before every write of an everyday slot (protect) – so a wrong A2 cannot create an unusable slot.
            Since 11.1; identities from 11.0 do not have it yet and receive it on the next everyday unlock or the
            next step-up confirmation (in each case only once A2 has been proven).
chk.pw    : finding H1 – a shared passphrase must not be the identity passphrase (checked without the passphrase
            being in the session). Stored only encrypted inside the content. Since 11.4 Argon2id (RFC 9106, second
            recommended option: 3 passes, 64 MiB; only these values are accepted) instead of HMAC-SHA256 (CodeQL
            alert #3). Not 1 GiB, because the value is computed once per stored partner on loading.
            Without "pwk" (identities from 11.0–11.3) chk.pw = hex(HMAC-SHA256(pw_salt, pw')); this value is only read
            and is replaced (new salt) as soon as the passphrase is proven via chk.a: when opening in mode 3, via the
            emergency package or at step-up confirmation. The app then saves immediately.
```
Writing back: same salt and key, new random nonce (AES-GCM-SIV: even an accidental nonce repetition violates neither
confidentiality nor integrity, TR-02102-1 section 3.1.2), atomic file replacement; beforehand a check that the file
has not changed since it was opened.

## Self-test at start-up
RFC 8452 vector (AES-GCM-SIV), FIPS 202 vector (SHA3-256), HKDF-SHA-512 against an independent hmac computation,
hybrid KEM against tests/vectors/hkem_v3.txt (keys from seed and decapsulation), signature keys from fixed seeds,
round trip and rejection of falsified signatures. Since 11.2 additionally known-answer values from foreign
implementations (sigillum/data/kat_fremd.json, generated without OpenSSL/libsodium): ECDSA-brainpoolP512r1-SHA3-512 from
own curve arithmetic per RFC 5639, ML-DSA-87 key and signature from dilithium-py (FIPS 204, with context), Argon2id
from argon2-cffi (RFC 9106). On any deviation the app does not start.

## Mode 5 – identity file with YubiKey (optional, v11: everyday use without passphrase)
```
A       = Argon2id as in mode 3 (purpose "identity")                       (passphrase + PIN + key file)
A2      = Argon2id("SIGILLUM-ARCANUM-v3\0" | lp("daily") | lp(NFC(pin).strip()) | lp(keyfile_secret32), salt16,
          ops = 4, mem = 2^30)                                              (PIN + key file, WITHOUT passphrase)
header  = "SA" | 0x03 | 0x05 | ops | memlog | salt16 | prf_s32 | count(1) | slot* | nonce12
slot    = type(1) | meta_len(2) | meta | nonce12 | AES-256-GCM-SIV(KEK, M, aad)(48)
          type 3 = everyday (YubiKey): meta = cred_id (1–1023 bytes); secret = WebAuthn PRF(prf_s) (32 bytes); base = A2
          type 2 = emergency:          meta = code_id16;              secret = emergency code (32 bytes);  base = A
          type 1 = YubiKey slot up to version 10.1 (base A) – rejected (“older app version”)
KEK     = HKDF-SHA-512(ikm = base | secret, salt = empty,
                       info = "SIGILLUM-v3-slot" | type | h3("SIGILLUM-v3-slot-meta", meta, 32))
aad     = header[0:6] | salt16 | prf_s32 | type | meta
content = AES-256-GCM-SIV(M, nonce, as in mode 3, aad = header)
```
Exactly 1 emergency slot and 1–4 everyday slots, no duplicate cred_id; anything else is rejected.
M and prf_s are rolled anew on every change of the slots. Every change (on/off, replace key, renew package) requires
A and A2 from passphrase + PIN + key file; A is checked against chk.a, otherwise nothing is changed.
Factors in everyday use: key file (possession), YubiKey (possession, hardware), FIDO PIN (knowledge, protected against
brute force inside the key), app PIN (knowledge). Without the YubiKey secret an offline attacker is missing 256 bits.
FIDO credential: RP ID "sigillum-arcanum.invalid" (RFC 2606, never resolvable), authenticatorAttachment
"cross-platform", hint "security-key", transport "usb", residentKey "discouraged", credProtect
"userVerificationRequired" (enforced), userVerification "required"; the UV flag of the response is checked. State
"recovery_pending" (bool) = emergency code used, renewal pending.
PRF per WebAuthn: hmac-secret salt = SHA-256("WebAuthn PRF" | 0x00 | prf_s); hmac-secret computes inside the YubiKey
with HMAC-SHA-256 (CTAP 2.1, not changeable; HMAC-SHA-256 is recommended per TR-02102-1 table 5.1).

## Emergency package
```
part   = "SASHP3" | set4 | x | k | n | y160 | bind32 | h3("SIGILLUM-SHARE-CHK", everything before, 4)
         Shamir 2-of-3 over F_p, p = 2^1279 - 1, per TR-02102-1 chapter 7 (tables 7.1/7.2):
         a0 = int(identity keyfile44 | code_id16 | emergency code32), a1 uniform from {0..p-1},
         y = f(x) mod p (big-endian, 160 bytes), x = 1..3
bind32 = h3("SIGILLUM-SHRC", set4 | key file | code_id | code, 32), identical in every part
```
On combining, the result must match the binding value; with three parts a falsified part is skipped.
Parts of different kinds (SASHP1/SASHP3) or sets are not mixed; older formats (SASHR1–3) are rejected.
On combining, a0 < 2^(8·92) must hold, otherwise the parts are considered mismatched.
Output: PDFs for printing (overwritten and deleted after confirmation), files only optional, each part in its own
folder.

## Hybrid KEM (ML-KEM-1024 + ECDH-brainpoolP512r1)
```
expand(seed32): e = SHAKE256(lp("SIGILLUM-v3-HKEM-expand") | seed, 160)
                sk_M = ML-KEM-1024.KeyGen_internal(d = e[0:32], z = e[32:64])
                d_X  = (int(e[64:160]) mod (q - 1)) + 1                     (768 bits -> bias < 2^-256)
ek1 = pk_M(1568)        ek2 = 04 | x64 | y64 (129)        pk = ek1 | ek2 (1697)
Encapsulation: (K1, c1) = ML-KEM-1024.Encaps(ek1); ephemeral key e; c2 = e·G (129); K2 = x(e·ek2) (64)
ct  = c1(1568) | c2(129) (1697)
K   = HKDF-SHA-512(ikm = K1 | K2 | c1 | c2 | ek1 | ek2, salt = empty, info = domain_sep, L = 32)
domain_sep = "SIGILLUM-ARCANUM-v3/HKEM/ML-KEM-1024+ECDH-brainpoolP512r1/SP800-227-KeyCombine/HKDF-SHA-512"
```
KeyCombine per NIST SP 800-227, section 4.6.2, eq. (15): H(K1, K2, c1, c2, ek1, ek2, domain_sep), H = KDF – permitted
per TR-02102-1 table 2.1. All inputs have fixed length. Point validation: uncompressed only (0x04), fixed length, on
the curve, not the point at infinity (cofactor 1). There is no official test vector for this combination; the app
checks against its own known-answer test (tests/vectors/hkem_v3.txt) and the test recomputes the combiner
independently (own HKDF implementation).

## Hybrid signature (TR-02102-1 section 5.3.4)
```
sig = ECDSA-brainpoolP512r1-SHA3-512(lp(ctx) | data) as r64 | s64   |   ML-DSA-87.Sign(data, ctx) (4627, hedged, pure)
```
Valid only if BOTH are valid; 0 < r < q and 0 < s ≤ ⌊q/2⌋ (canonical low-s form, finding R8-H3) are required before
verification; when signing, s > q/2 is replaced by q − s. Signature keys are used for this purpose only.
ECDSA key: d = (int(SHAKE256(lp("SIGILLUM-v3-ECDSA-expand") | ecdsa_seed32, 96)) mod (q-1)) + 1.

## Mode 6 – contact message with one-time keys (since 11.2, R12-N1; only mode 6 is sent)
As mode 4 (below), but header[3] = 0x06 and the announcement contains a pool of 5 keys:
```
announcement = seq8 | 0x05 | 5 × (id8 | hkem_pk1697)        (ids distinct, never 0^8; every key validated)
Sender:     uses keys 1–4 of the newest announcement EXACTLY ONCE each, then key 5 (fallback) for all further
            messages until a newer announcement from the recipient arrives.
Recipient:  keys 1–4 are one-time keys: deleted immediately after opening (in addition, all keys of older
            announcements as in mode 4). h3("SIGILLUM-SPENT", header, 16) is remembered so that a second copy is
            recognised as “already opened” – its content can no longer be read (intended).
```
Mode 4 (up to 11.1) is still read and answered (its single key counts as the fallback key).
At most 1000 own open keys per contact.

## Mode 4 – contact message with key rotation (up to 11.1)
```
header = "SA" | 0x03 | 0x04 | hkem_ct1697 | nonce12                 (no sender/recipient/key ID)
target = newest key announced by the recipient (id8, pk) or their base key (id = 0^8)
key    = HKDF-SHA-512(ikm = K, salt = empty, info = "SIGILLUM-v3-msg" | header[0:4] | recipient_fp32 | target_id8)
announcement = seq8 | new_id8 | new_hkem_pk1697
signed = "SIGILLUM-ARCANUM-v3-sig" | header | recipient_fp32 | sender_fp32 | announcement | inner
plain  = sender_fp32 | hybrid signature(signed, ctx = "SIGILLUM-ARCANUM-v3-sig") 4755 | announcement | inner
blob   = header | AES-256-GCM-SIV(key, nonce, plain, aad = header)
```
Receiving (state is only applied on full success and only after saving):
1. Try all own keys (base + open rotation keys of all contacts, ≤ 1000 per contact).
2. The sender must be in the contact book and verified; if the key used belongs to a contact, it must be exactly that
   contact. Both signatures must be valid; the inner sender must match.
3. Apply the announcement if `seq` is larger than before. Partner restart: a message to the base key with a newer
   timestamp → delete own rotation keys for them. An older base message → replay, nothing applied.
4. Delete own rotation keys with a smaller `seq` than the one used immediately.
5. Gap in the partner's `seq` → ask before deleting; several messages are sorted by `seq`.
   The gap is tracked as a count; at most 20 numbers are listed individually. Valid: 0 < seq < 2^63.
6. Message already in "seen" → report as replay, apply nothing. After a restart (no key state): a message to the base
   key with timestamp ≤ lower bound → replay. Timestamps count at most 10 minutes beyond the time of receipt.
7. Announced keys (and base keys on import): ML-KEM modulus check and EC point validation.

Public key: `"SAPUB3" | lp(name) | hkem_pk1697 | ecdsa_pk129 | mldsa87_pk2592` (canonical only).
Fingerprint: `h3("SIGILLUM-FP-v3", pubbundle, 32)`, displayed in full (64 hex characters).
Names: 1–64 characters, no control characters, no mixing of scripts; look-alike comparison via a skeleton form.

## Representation
Bytes → 5-bit values (MSB first). Value v → glyph U+E000 + 32·f + v with random form f ∈ {0..3}, or RFC 4648 Base32.
On input only exactly these characters (Base32 also lower case) and whitespace count; everything else is rejected.

## Backup
Shamir 2-of-3 over F_p with p = 2^521 - 1 (TR-02102-1 chapter 7), a0 = int(keyfile44).
Part = `"SASHP1" | set_id4 | x | k | n | y66 | h3("SIGILLUM-SHARE-CHK", everything before, 4)`; strict checks of
length, x, k, n, set, y < p. Both primes are proven in the tests with Lucas–Lehmer.
Restoring (finding R8-H4): every pair is combined and checked via the ID and checksum of the key file. With three
parts all must lie on the same line; otherwise the consistent pair is used and the deviating (or unreadable) part is
reported. Contradictory results → nothing is restored.
Deliberately no plain hash in the parts – a single part remains information-theoretically meaningless.

## Hand mode v2
Field GF(32) with x^5 + x^2 + 1. Sheet: masks m1..m4; per row i: v_i, k_1i..k_4i (all uniform, single use).
```
p       = [B ÷ 32, B mod 32] | text values | padding with 31 to a multiple of 20    (B = number of values after padding / 10)
c_i     = p_i XOR v_i
t_j     = m_j XOR (k_j1 × p_1) XOR … XOR (k_jn × p_n)        j = 1..4,  × in GF(32)
message = c_1..c_n | t_1..t_4
```
A forgery without the sheet succeeds with probability at most 32^-4; the block count at the start protects against
truncation and extension. Sheet no.: 64 random bits.
```
sheet_code = Base32( sid13 | m1..m4 | (v_i, k_1i..k_4i) per row | check10 )
sid13      = sheet no. as 13 values of 5 bits (65 bits, top bit 0)
check10    = upper 50 bits of h3("SIGILLUM-SHEET", all preceding values, 8)
```
On input: checksum, valid sheet size (2 + 10·B rows, B = 2–60) and agreement with the typed sheet no. must hold.
Register: message ID = h3("SIGILLUM-HMSG", ciphertext values, 16).
The checksum exists only in the (secret) sheet code, never in a message – perfect secrecy is unaffected.

## Quick unlock (v11, optional, memory only)
```
on unlock (only if turned on):  q_salt16 random, Kq = Argon2id("SIGILLUM-ARCANUM-v3\0" | lp("quick") |
                                lp(NFC(pin).strip()), q_salt16, ops = 4, mem = 2^30)
on automatic lock:              sealed = nonce12 | AES-256-GCM-SIV(Kq, session_json, aad = "SIGILLUM-v11-quick")
session_json = {name, secret, state, key (A or null), dkey (A2 or null), salt, kf, prot}
```
At most 3 PIN attempts (as in TR-02102-1 table 6.2, but enforced only within the app), then discarded. Also discarded
on manual lock, on closing, and if the identity file has changed since locking (SHA-256 of the file content; checked
BEFORE unsealing, so that the message reveals nothing about the PIN). Nothing is sealed while the identity is open via
the emergency package or while renewal of the emergency code is pending. On restore, key and salt lengths are checked
(32 and 16 bytes). Never stored.

## Local settings (not secret)
`%APPDATA%\SigillumArcanum\einstellungen.json`: device ID, device-specific HMAC IDs of used key files (H1), of printed
backups and exported identities, IDs of seen shared messages, interface (theme, lock time 5/10/15/30 minutes, quick
unlock on/off, language "de"/"en" since 11.3), last used PATHS of identity file and key file, per identity (as HMAC
ID) the highest write generation seen (11.2, R12-N4: warning when opening an older version). No passphrases, PINs or
keys. Invalid values are reset (an invalid language falls back to the detected system language).
