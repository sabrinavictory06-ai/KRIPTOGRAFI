
import math
import random
import time

rng = random.Random(11)


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


def buat_kunci(bits_prima, e=65537):
    while True:
        p, q = gen_prime(bits_prima), gen_prime(bits_prima)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            return p, q, e, pow(e, -1, phi)


def pollard_rho(n):
    """Mengembalikan (faktor, jumlah_iterasi)."""
    if n % 2 == 0:
        return 2, 1
    c = 1
    while True:
        x = y = 2
        d, it = 1, 0
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            it += 1
        if d != n:
            return d, it
        c += 1


p, q, e, d = buat_kunci(32)
n, phi = p * q, (p - 1) * (q - 1)
print("=== 1. Pembentukan kunci (prima acak 32 bit) ===")
print(f"  n={n}  e={e}  d={d}")
print(f"  n == p*q: {n == p * q} | gcd(e,phi)=1: {math.gcd(e, phi) == 1} | e*d mod phi = {e * d % phi}")

print("\n=== 2. Enkripsi teks per blok (textbook RSA) ===")
pesan = "HALO"
m = int.from_bytes(pesan.encode(), "big")
c1, c2 = pow(m, e, n), pow(m, e, n)
print(f"  m={m}  c={c1}  dekripsi={pow(c1, d, n).to_bytes(4, 'big').decode()}")
print(f"  Enkripsi dua kali menghasilkan ciphertext sama (deterministik): {c1 == c2}")

print("\n=== 3. Malleability: ciphertext dimodifikasi tanpa kunci ===")
c_palsu = c1 * pow(2, e, n) % n
print(f"  c' = c * 2^e mod n -> dekripsi = {pow(c_palsu, d, n)}  (2*m = {2 * m})")

print("\n=== 4. Memilih e yang tidak valid ===")
for e_uji in (7, 12):
    sah = math.gcd(e_uji, phi) == 1
    print(f"  e={e_uji:<3}: gcd(e, phi) = {math.gcd(e_uji, phi)} -> {'valid' if sah else 'DITOLAK, d tidak ada'}")

print("\n=== 5. Ukuran n menentukan: faktorisasi dengan Pollard rho ===")
print(f"  {'bit n':>6} | {'iterasi':>9} | {'waktu':>8}")
for bits in (32, 48, 64, 80):
    pp, qq, _, _ = buat_kunci(bits // 2)
    t = time.perf_counter()
    _, it = pollard_rho(pp * qq)
    print(f"  {bits:>6} | {it:>9,} | {time.perf_counter() - t:6.3f} s")
print("  Untuk RSA-2048, metode ini butuh ~2^512 iterasi: tidak mungkin.")

print("\n=== 6. Mematahkan RSA 64 bit tanpa private key ===")
faktor, _ = pollard_rho(n)
d_curian = pow(e, -1, (faktor - 1) * (n // faktor - 1))
print(f"  Faktor ditemukan: {faktor} x {n // faktor}")
print(f"  d hasil curian == d asli: {d_curian == d} | dekripsi: {pow(c1, d_curian, n).to_bytes(4, 'big').decode()}")
