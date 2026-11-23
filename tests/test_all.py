import hashlib
import itertools
import os
import random
import unicodedata

import pytest

from sigillum import codec, core, shamir

PW = "abacus zoom t-shirt yo-yo kettle velvet ample"      # 7 Wörter aus der Liste
PIN = "471100"
DEV = b"\x11" * 16
HERE = os.path.dirname(__file__)


@pytest.fixture(scope="module")
def kf():
    return core.new_keyfile()


# ---------- Testvektoren
def test_aes256_gcm_siv_vectors():
    """RFC 8452, Anhang C.2 (AEAD_AES_256_GCM_SIV): zwei Vektoren, Ver- und Entschlüsseln."""
    key = bytes.fromhex("01" + "00" * 31)
    nonce = bytes.fromhex("03" + "00" * 11)
    for pt, aad, res in (("0100000000000000", "", "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
                         ("0200000000000000", "01", "1de22967237a813291213f267e3b452f02d01ae33e4ec854")):
        pt, aad, res = bytes.fromhex(pt), bytes.fromhex(aad), bytes.fromhex(res)
        assert core._aead_encrypt(pt, aad, nonce, key) == res
        assert core._aead_decrypt(res, aad, nonce, key) == pt
        for i in range(len(res)):
            bad = bytearray(res)
            bad[i] ^= 1
            with pytest.raises(core.SigillumError):
                core._aead_decrypt(bytes(bad), aad, nonce, key)


def _hkdf_sha512_reference(ikm, info, length):
    """Unabhängige Nachrechnung von HKDF (RFC 5869) mit hmac/hashlib – Gegenprobe zur Bibliothek."""
    import hmac as _h
    prk = _h.new(b"\x00" * 64, ikm, hashlib.sha512).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = _h.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        out += t
        i += 1
    return out[:length]


def test_hkdf_rfc5869_style_cross_check():
    for ikm, info in ((b"a" * 32, b"x"), (bytes(200), b""), (os.urandom(77), os.urandom(40))):
        assert core.hkdf(ikm, info) == _hkdf_sha512_reference(ikm, info, 32)


def test_mersenne_primes_lucas_lehmer():
    for e in (521, 1279):
        m, s = 2 ** e - 1, 4
        for _ in range(e - 2):
            s = (s * s - 2) % m
        assert s == 0
    assert shamir.PRIME[shamir.SHARE_MAGIC] > 2 ** (8 * shamir.SECRET_LEN)
    assert shamir.PRIME[shamir.PACKAGE_MAGIC] > 2 ** (8 * shamir.PACKAGE_LEN)


def test_brainpool_order():
    """q = Ordnung des Basispunkts: (q-1)*G = -G und q*G nicht als Schlüssel zulässig."""
    from cryptography.hazmat.primitives.asymmetric import ec
    g = ec.derive_private_key(1, core.CURVE).public_key().public_numbers()
    m = ec.derive_private_key(core.EC_ORDER - 1, core.CURVE).public_key().public_numbers()
    assert g.x == m.x and g.y != m.y
    with pytest.raises(ValueError):
        ec.derive_private_key(core.EC_ORDER, core.CURVE)


def test_hybrid_kem_combiner_independent_recomputation():
    """SP 800-227 Gl. (15) unabhängig nachgerechnet: H(K1,K2,c1,c2,ek1,ek2,domain_sep) mit HKDF-SHA-512."""
    from cryptography.hazmat.primitives.asymmetric import ec
    k = core.HybridKey.generate()
    ss, ct = core.hkem_encap(k.pk)
    c1, c2 = ct[:1568], ct[1568:]
    k1 = k._m.decapsulate(c1)
    k2 = k._x.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(core.CURVE, c2))
    ek1, ek2 = k.pk[:1568], k.pk[1568:]
    want = _hkdf_sha512_reference(k1 + k2 + c1 + c2 + ek1 + ek2, core.HKEM_DOMAIN, 32)
    assert ss == want == k.decap(ct)
    assert len(k.pk) == len(ct) == 1697 and k.pk[1568] == 4


def test_hybrid_kem_kat():
    """Eigener Bekannt-Antwort-Test (fester Seed, festes Chiffrat) – erkennt jede Format-/Algorithmusänderung."""
    v = dict(line.strip().split("=", 1) for line in open(os.path.join(HERE, "vectors", "hkem_v3.txt")) if "=" in line)
    k = core.HybridKey(bytes.fromhex(v["seed"]))
    assert hashlib.sha3_256(k.pk).hexdigest() == v["pk_sha3"]
    assert k.decap(bytes.fromhex(v["ct"])).hex() == v["ss"]


def test_hybrid_kem_roundtrip_wrong_key_and_bad_points():
    a, b = core.HybridKey.generate(), core.HybridKey.generate()
    ss, ct = core.hkem_encap(a.pk)
    assert a.decap(ct) == ss and b.decap(ct) != ss
    with pytest.raises(core.SigillumError):
        core.hkem_encap(a.pk[:-1])
    for pos, val in ((1568, 2), (1568, 0), (1600, None), (len(a.pk) - 1, None)):
        bad = bytearray(a.pk)
        bad[pos] = val if val is not None else bad[pos] ^ 1
        with pytest.raises(core.SigillumError):
            core.hkem_check_pk(bytes(bad))
    bad = bytearray(ct)
    bad[-1] ^= 1                                     # EC-Punkt im Chiffrat nicht mehr auf der Kurve
    with pytest.raises(core.SigillumError):
        a.decap(bytes(bad))
    bad = bytearray(ct)
    bad[5] ^= 1                                      # ML-KEM-Teil verändert: implizite Ablehnung -> anderes ss
    assert a.decap(bytes(bad)) != ss


def test_hybrid_signature_both_required():
    i = core.Identity.generate("Anna")
    c = i.public()
    sig = i.sign(b"daten", b"ctx")
    assert len(sig) == core.SIG_LEN == 128 + 4627
    core.verify_hybrid(c, sig, b"daten", b"ctx")
    assert i.sign(b"daten", b"ctx") != sig           # beide Verfahren randomisiert ("hedged")
    other = core.Identity.generate("Anna").sign(b"daten", b"ctx")
    for bad in (other[:128] + sig[128:], sig[:128] + other[128:], sig[:-1], sig + b"\x00"):
        with pytest.raises(core.SigillumError):
            core.verify_hybrid(c, bad, b"daten", b"ctx")
    for data, ctx in ((b"datem", b"ctx"), (b"daten", b"cty")):
        with pytest.raises(core.SigillumError):
            core.verify_hybrid(c, sig, data, ctx)
    q = core.EC_ORDER
    for r, s_ in ((0, 1), (q, 1), (1, q), (1, 0)):
        with pytest.raises(core.SigillumError):
            core.verify_hybrid(c, r.to_bytes(64, "big") + s_.to_bytes(64, "big") + sig[128:], b"daten", b"ctx")


def test_identity_secret_roundtrip_deterministic():
    i = core.Identity.generate("Anna")
    j = core.Identity.from_secret("Anna", i.secret_bytes())
    assert j.public().to_bytes() == i.public().to_bytes()


def test_wordlist_integrity():
    wl = core.wordlist()
    assert len(wl) == 7776 and wl[0] == "abacus" and wl[-1] == "zoom"


# ---------- Passphrase (M4)
@pytest.mark.parametrize("pw", ["", "Mein Hund heißt Bello und ist 7 Jahre alt", "abacus zoom kettle velvet ample",
                                "abacus zoom kettle velvet ample xyzzy"])
def test_weak_passphrase_rejected(pw, kf):
    with pytest.raises(core.SigillumError):
        core.encrypt_shared("x", pw, PIN, kf, DEV)


def test_passphrase_canonical(kf):
    blob = core.encrypt_shared("x", PW, PIN, kf, DEV)
    assert core.decrypt_shared(blob, "  ABACUS  Zoom T-Shirt yo-yo kettle   velvet ample ", PIN, kf)["text"] == "x"
    for i in range(50):
        assert core.passphrase_bits(core.generate_passphrase()) > 90


def test_pin_minimum(kf):
    with pytest.raises(core.SigillumError):
        core.encrypt_shared("x", PW, "12", kf, DEV)


# ---------- Darstellung
@pytest.mark.parametrize("n", [0, 1, 4, 5, 7, 8, 31, 100, 333])
def test_codec_roundtrip(n):
    data = bytes(random.getrandbits(8) for _ in range(n))
    for latin in (False, True):
        assert codec.decode(codec.encode(data, latin)) == data


def test_codec_forms_vary_and_limit():
    data = b"\x00" * 60
    assert codec.encode(data) != codec.encode(data)
    with pytest.raises(ValueError):
        codec.decode("A" * (codec.MAX_CHARS + 1))


# ---------- Modus 1
def test_shared_roundtrip_and_sender(kf):
    blob = core.encrypt_shared("Treffen um 14:30 – grüße!", PW, PIN, kf, DEV)
    r = core.decrypt_shared(blob, PW, PIN, kf)
    assert r["text"] == "Treffen um 14:30 – grüße!" and r["sender"] == DEV


def test_same_text_differs(kf):
    assert core.encrypt_shared("x", PW, PIN, kf, DEV) != core.encrypt_shared("x", PW, PIN, kf, DEV)


def test_wrong_factors_fail(kf):
    blob = core.encrypt_shared("geheim", PW, PIN, kf, DEV)
    for args in [(PW.replace("zoom", "zone"), PIN, kf), (PW, "4712", kf), (PW, PIN, core.new_keyfile())]:
        with pytest.raises(core.SigillumError):
            core.decrypt_shared(blob, *args)


def test_tamper_detected(kf):
    blob = core.encrypt_shared("geheim", PW, PIN, kf, DEV)
    for pos in (3, 10, 50, len(blob) - 1):
        b = bytearray(blob)
        b[pos] ^= 1
        with pytest.raises(core.SigillumError):
            core.decrypt_shared(bytes(b), PW, PIN, kf)


def test_nfc_normalisation(kf):
    pin = "Grüße!!"
    blob = core.encrypt_shared("x", PW, pin, kf, DEV)
    assert core.decrypt_shared(blob, PW, unicodedata.normalize("NFD", pin), kf)["text"] == "x"


def test_length_hidden(kf):
    assert len(core.encrypt_shared("a", PW, PIN, kf, DEV)) == len(core.encrypt_shared("a" * 80, PW, PIN, kf, DEV))


def test_keyfile_checks():
    k = bytearray(core.new_keyfile())
    k[20] ^= 1
    with pytest.raises(core.SigillumError):
        core.read_keyfile(bytes(k))


def test_purpose_separation(kf):
    """Gleiche Faktoren ergeben für Identität und Nachrichten verschiedene Schlüssel."""
    salt = b"\x00" * 16
    assert (core.derive_key(PW, PIN, kf, salt, core.PURPOSE_SHARED)
            != core.derive_key(PW, PIN, kf, salt, core.PURPOSE_IDENTITY))


def test_old_format_rejected():
    for v in (1, 2):
        with pytest.raises(core.SigillumError, match="älteren App-Version"):
            core.message_mode(b"SA" + bytes([v, 1]) + bytes(100))


@pytest.mark.realkdf
def test_real_parameters_end_to_end(kf):
    blob = core.encrypt_shared("echt", PW, PIN, kf, DEV)
    assert blob[4:6] == bytes([4, 30])
    assert core.decrypt_shared(blob, PW, PIN, kf)["text"] == "echt"


# ---------- Identitäten
def test_fingerprint_256bit_and_name():
    p = core.Identity.generate("Anna").public()
    assert len(core.normalize_fingerprint(p.fingerprint())) == 64
    q = core.Contact("Anna2", p.kem_pk, p.e_pub, p.d_pub)
    assert p.fingerprint() != q.fingerprint()


def test_contact_file_strict():
    p = core.Identity.generate("Anna").public()
    b = p.to_bytes()
    assert core.Contact.from_bytes(b).to_bytes() == b
    for bad in (b[:8], b[:-1], b + b"\x00", b"SAPUB3\x00\x00\x00\x01\xff" + b[11:], b"SAPUB2" + b[6:]):
        with pytest.raises(core.SigillumError):
            core.Contact.from_bytes(bad)


@pytest.mark.parametrize("name", ["", " ", "a" * 65, "Anna\x00", "Ben‮"])
def test_bad_names(name):
    with pytest.raises(core.SigillumError):
        core.Identity.generate(name)


# ---------- Shamir
def test_shamir_all_pairs():
    kf = core.new_keyfile()
    parts = shamir.split(kf)
    for pair in itertools.permutations(parts, 2):
        assert shamir.combine(list(pair)) == kf
    assert shamir.combine(parts) == kf
    with pytest.raises(ValueError):
        shamir.combine([parts[0]])
    with pytest.raises(ValueError):
        shamir.combine([parts[0], parts[0]])


def _resign(body):
    return body + shamir._chk(body)


def test_shamir_strict():
    parts = shamir.split(core.new_keyfile())
    body = parts[1][:-4]
    bad_len = _resign(body + b"\x00")
    x0 = bytearray(body)
    x0[10] = 0
    k1 = bytearray(body)
    k1[11] = 1
    other_set = shamir.split(core.new_keyfile())[1]
    for bad in (bad_len, _resign(bytes(x0)), _resign(bytes(k1)), other_set):
        with pytest.raises(ValueError):
            shamir.combine([parts[0], bad])
    with pytest.raises(ValueError):
        shamir.combine([])


def test_shamir_single_share_uniform():
    """Ein einzelner Teil ist gleichverteilt: obere Bytes des Werts y (< 2^521-1) für festes Geheimnis."""
    counts = [0] * 256
    kf = core.new_keyfile()
    for _ in range(20000):
        counts[shamir.split(kf)[0][13 + 1]] += 1      # Byte 1 von y (Byte 0 hat nur 1 Bit)
    assert max(counts) < 3 * 20000 / 256 and min(counts) > 20000 / 256 / 3


def test_foreign_kdf_parameters_rejected(kf):
    """Befund L2: Speicher-/Rechenaufwand wird nie aus der Datei übernommen."""
    blob = bytearray(core.encrypt_shared("x", PW, PIN, kf, DEV))
    for ops, mem in ((10, 31), (4, 30), (1, 27), (2, 26)):
        b = bytearray(blob)
        b[4], b[5] = ops, mem
        with pytest.raises(core.SigillumError, match="Parameter"):
            core.decrypt_shared(bytes(b), PW, PIN, kf)


def test_r3_3_codec_exact_characters():
    for ch in ("ﬆ", "ﬅ", "ß", "İ", "ı", "Ａ", "２"):
        with pytest.raises(ValueError):
            codec.text_to_values(ch)
    assert codec.text_to_values("aZ27 \n") == [0, 25, 26, 31]


def test_self_test_passes_and_detects_broken_primitive(monkeypatch):
    core.self_test()
    monkeypatch.setattr(core, "_aead_encrypt", lambda p, a, n, k: b"\x00" * (len(p) + 16))
    with pytest.raises(core.SigillumError, match="Selbsttest"):
        core.self_test()


def test_old_keyfile_clear_message():
    with pytest.raises(core.SigillumError, match="älteren App-Version"):
        core.read_keyfile(b"SAKEY1\x00\x00" + bytes(36))


def test_mlkem1024_modulus_check():
    """FIPS 203 Eingabeprüfung: Koeffizient >= q = 3329 im öffentlichen Schlüssel wird abgelehnt."""
    pk = bytearray(core.HybridKey.generate().pk)
    pk[0], pk[1] = 0xFF, pk[1] | 0x0F                  # erster 12-Bit-Koeffizient = 4095
    with pytest.raises(core.SigillumError):
        core.hkem_check_pk(bytes(pk))


def test_message_sizes_documented():
    """Größen laut FORMAT.md."""
    from sigillum import ratchet
    assert (core.HKEM_PK, core.HKEM_CT, core.SIG_LEN, ratchet.HDR_LEN) == (1697, 1697, 4755, 4 + 1697 + 12)


def test_self_test_detects_wrong_kat(monkeypatch):
    monkeypatch.setattr(core, "_KAT_HKEM_SS", "00" * 32)
    with pytest.raises(core.SigillumError, match="Hybrid-KEM"):
        core.self_test()


# ---------- Befunde der achten Prüfrunde
def test_r8_n1_short_files_clean_error():
    from sigillum import ratchet
    for blob in (b"SA", b"SA\x03", b"SA\x03\x05", b"SA\x03\x05\x04", b"SA\x03\x03\x04"):
        with pytest.raises(core.SigillumError):
            ratchet.parse_fido_header(blob)
        with pytest.raises(core.SigillumError):
            ratchet.Vault.open(blob, PW, PIN, core.new_keyfile())


def test_r8_h3_low_s_only():
    i = core.Identity.generate("Anna")
    c = i.public()
    for _ in range(20):
        sig = i.sign(b"m", b"c")
        assert int.from_bytes(sig[64:128], "big") <= core.EC_ORDER // 2
        core.verify_hybrid(c, sig, b"m", b"c")
        high = sig[:64] + (core.EC_ORDER - int.from_bytes(sig[64:128], "big")).to_bytes(64, "big") + sig[128:]
        with pytest.raises(core.SigillumError):
            core.verify_hybrid(c, high, b"m", b"c")


def test_r8_h4_keyfile_backup_all_pairs():
    kf = core.new_keyfile()
    parts = shamir.split(kf)
    for n in (2, 3):
        for combo in itertools.permutations(parts, n):
            assert shamir.combine_keyfile(list(combo)) == (kf, [])
    for bad_idx in range(3):
        for pos in (14, 13 + 33, 13 + 65):                    # y vorn, Mitte, hinten
            b = bytearray(parts[bad_idx][:-4])
            b[pos] ^= 0x5A
            forged = _resign(bytes(b))
            trio = list(parts)
            trio[bad_idx] = forged
            got, suspect = shamir.combine_keyfile(trio)
            assert got == kf and suspect == [bad_idx]
            with pytest.raises(ValueError):
                shamir.combine_keyfile([forged, parts[(bad_idx + 1) % 3]])
        unreadable = list(parts)
        unreadable[bad_idx] = parts[bad_idx][:-1] + bytes([parts[bad_idx][-1] ^ 1])   # Tippfehler -> Prüfsumme
        assert shamir.combine_keyfile(unreadable) == (kf, [bad_idx])
    other = shamir.split(kf)
    with pytest.raises(ValueError):
        shamir.combine_keyfile([parts[0], other[1]])          # anderer Satz
    two_bad = [parts[0]] + [_resign(bytes(bytearray(p[:-4])[:20]) + bytes([p[20] ^ 1]) + p[21:-4]) for p in parts[1:]]
    with pytest.raises(ValueError):
        shamir.combine_keyfile(two_bad)
