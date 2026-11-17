
import math
import string

A = string.ascii_uppercase
KATA_UMUM = ["YANG", "DAN", "DI", "KE", "DARI", "INI", "ITU", "UNTUK", "DENGAN", "PADA", "KUNCI"]


def egcd(a, b):
    """Mengembalikan (g, x, y) sehingga a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inv(a, n=26):
    g, x, _ = egcd(a % n, n)
    return x % n if g == 1 else None


def affine_enc(teks, a, b):
    if math.gcd(a, 26) != 1:
        raise ValueError(f"a={a} tidak valid: gcd({a}, 26) = {math.gcd(a, 26)}")
    return "".join(A[(a * A.index(c) + b) % 26] if c in A else c for c in teks)


def affine_dec(teks, a, b):
    inv = mod_inv(a)
    return "".join(A[(inv * (A.index(c) - b)) % 26] if c in A else c for c in teks)


def skor(teks):
    return sum(teks.split().count(k) for k in KATA_UMUM)


def brute_force(cipher):
    hasil = []
    for a in range(1, 26):
        if math.gcd(a, 26) != 1:
            continue
        for b in range(26):
            p = affine_dec(cipher, a, b)
            hasil.append((skor(p), a, b, p))
    hasil.sort(reverse=True)
    return hasil


if __name__ == "__main__":
    print("=== 1. Modulo (hasil selalu 0..n-1, termasuk bilangan negatif) ===")
    for x, n in [(47, 9), (-7, 26), (100, 26)]:
        print(f"  {x} mod {n} = {x % n}  (q={x // n}, r={x % n})")

    print("\n=== 2. Kunci a yang valid untuk mod 26 ===")
    valid = [(a, mod_inv(a)) for a in range(1, 26) if math.gcd(a, 26) == 1]
    print("  Jumlah kunci valid :", len(valid))
    print("  (a, inverse)       :", valid)
    print("  Tidak valid        :", [a for a in range(1, 26) if math.gcd(a, 26) != 1])

    print("\n=== 3. Kenapa a=13 tidak boleh? (dua huruf -> satu ciphertext) ===")
    print("  B ->", A[(13 * 1 + 4) % 26], "| D ->", A[(13 * 3 + 4) % 26], "(a=13, b=4) -> bentrok!")

    print("\n=== 4. Enkripsi & dekripsi Affine ===")
    P = "KUNCI YANG VALID MEMBUAT PESAN DAPAT DIKEMBALIKAN DARI CIPHERTEXT INI"
    a, b = 17, 9
    C = affine_enc(P, a, b)
    print("  Plaintext :", P)
    print(f"  Kunci     : a={a}, b={b}, inverse(a)={mod_inv(a)}")
    print("  Ciphertext:", C)
    print("  Dekripsi  :", affine_dec(C, a, b))

    print("\n=== 5. Coba a=4 (tidak valid) ===")
    try:
        affine_enc("HALO", 4, 1)
    except ValueError as e:
        print("  Error:", e)

    print("\n=== 6. Brute force seluruh ruang kunci ===")
    hasil = brute_force(C)
    print("  Total kunci diuji:", len(hasil))
    for s, aa, bb, p in hasil[:3]:
        print(f"  skor={s:2d} a={aa:2d} b={bb:2d} -> {p[:45]}")
