
import hashlib
import hmac
import math
import random
import time

rng = random.Random(7)


def is_prime(n):
    if n < 2:
        return False
    kecil = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for s in kecil:
        if n % s == 0:
            return n == s
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in kecil:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(c):
            return c


def brute_dlog(g, y, p):
    nilai, langkah = 1, 0
    while nilai != y:
        nilai = nilai * g % p
        langkah += 1
    return langkah


def bsgs(g, y, p):
    """Baby-step giant-step: sekitar sqrt(p) langkah, bukan p langkah."""
    m = math.isqrt(p) + 1
    tabel, nilai = {}, 1
    for j in range(m):
        tabel.setdefault(nilai, j)
        nilai = nilai * g % p
    faktor = pow(g, -m, p)
    gamma = y
    for i in range(m + 1):
        if gamma in tabel:
            return i * m + tabel[gamma], m + i
        gamma = gamma * faktor % p
    return None, 2 * m


def kunci_dari(shared):
    return hashlib.sha256(str(shared).encode()).digest()


def xor_toy(kunci, data):
    """Cipher mainan (keystream SHA-256) agar pesan dapat dienkripsi di demo."""
    out = bytearray()
    for i, byte in enumerate(data):
        blok = hashlib.sha256(kunci + (i // 32).to_bytes(4, "big")).digest()
        out.append(byte ^ blok[i % 32])
    return bytes(out)


print("=== 1. Pertukaran kunci DH (p = 2^127 - 1) ===")
p, g = 2**127 - 1, 3
a, b = rng.randrange(2, p - 1), rng.randrange(2, p - 1)
A, B = pow(g, a, p), pow(g, b, p)
ka, kb = pow(B, a, p), pow(A, b, p)
print(f"  Publik : A={hex(A)[:14]}..., B={hex(B)[:14]}...")
print(f"  Rahasia: a dan b tidak pernah dikirim")
print(f"  Kunci Alice == Bob : {ka == kb}  (SHA-256: {kunci_dari(ka).hex()[:16]}...)")

print("\n=== 2. Serangan discrete log: brute force vs baby-step giant-step ===")
print(f"  {'bit p':>6} | {'brute force (langkah, detik)':<30} | BSGS (langkah, detik)")
for bits in (16, 20, 24, 32, 40):
    pp = gen_prime(bits)
    x = pp // 2 + rng.randrange(1000)
    y = pow(2, x, pp)
    if bits <= 24:
        t = time.perf_counter(); st = brute_dlog(2, y, pp)
        brute = f"{st:>10,} {time.perf_counter() - t:7.3f} s"
    else:
        brute = f"{'(dilewati: terlalu lama)':<30}"
    t = time.perf_counter(); _, st2 = bsgs(2, y, pp)
    print(f"  {bits:>6} | {brute:<30} | {st2:>8,} {time.perf_counter() - t:7.3f} s")
print(f"  Untuk p 2048 bit, BSGS butuh ~2^1024 langkah (angka {len(str(1 << 1024))} digit).")

print("\n=== 3. MITM aktif: Mallory berada di tengah ===")
m = rng.randrange(2, p - 1)
M = pow(g, m, p)                       # Mallory mengirim M ke Alice dan Bob
k_alice, k_bob = pow(M, a, p), pow(M, b, p)
k_m_alice, k_m_bob = pow(A, m, p), pow(B, m, p)
print(f"  Kunci Alice sama dengan kunci Bob? {k_alice == k_bob}  (keduanya mengira sama)")
print(f"  Mallory tahu kunci Alice: {k_m_alice == k_alice}, kunci Bob: {k_m_bob == k_bob}")
asli = b"TRANSFER Rp500000 KE REK 1234"
sampai_mallory = xor_toy(kunci_dari(k_alice), asli)
terbaca = xor_toy(kunci_dari(k_m_alice), sampai_mallory)
diubah = terbaca.replace(b"1234", b"9999")
sampai_bob = xor_toy(kunci_dari(k_m_bob), diubah)
print("  Alice mengirim :", asli.decode())
print("  Mallory membaca:", terbaca.decode())
print("  Bob menerima   :", xor_toy(kunci_dari(k_bob), sampai_bob).decode())

print("\n=== 4. Pertahanan: nilai publik diautentikasi (HMAC, kunci bersama K0) ===")
K0 = b"rahasia-yang-sudah-dibagi-sebelumnya"
tag = lambda v: hmac.new(K0, str(v).encode(), hashlib.sha256).digest()
print("  A asli dari Alice  -> verifikasi Bob:", hmac.compare_digest(tag(A), tag(A)))
print("  M palsu dari Mallory (tag tebakan) :", hmac.compare_digest(tag(M), hmac.new(b"salah", str(M).encode(), hashlib.sha256).digest()))
print("  (Di dunia nyata: tanda tangan digital + sertifikat/PKI, bukan K0 bersama.)")
