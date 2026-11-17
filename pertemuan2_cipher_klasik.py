
import string
from collections import Counter

A = string.ascii_uppercase

REFERENSI = (
    "BAHASA INDONESIA DIGUNAKAN OLEH BANYAK ORANG DI SELURUH NEGERI UNTUK BERKOMUNIKASI "
    "DALAM KEHIDUPAN SEHARI HARI MULAI DARI BERBELANJA DI PASAR BELAJAR DI SEKOLAH SAMPAI "
    "BEKERJA DI KANTOR SETIAP HARI KITA MEMBACA BERITA MENULIS PESAN DAN BERCERITA KEPADA "
    "TEMAN KELUARGA YANG KITA SAYANGI KEAMANAN DATA ADALAH HAL YANG PENTING AGAR INFORMASI "
    "PRIBADI TIDAK DISALAHGUNAKAN OLEH PIHAK YANG TIDAK BERHAK"
)


def profil(teks):
    huruf = [c for c in teks if c in A]
    cnt = Counter(huruf)
    return {c: (cnt[c] + 0.5) / (len(huruf) + 13) for c in A}  # smoothing


FREK_ID = profil(REFERENSI)


def geser(teks, k):
    return "".join(A[(A.index(c) + k) % 26] if c in A else c for c in teks)


def chi_square(teks):
    huruf = [c for c in teks if c in A]
    n = len(huruf) or 1
    cnt = Counter(huruf)
    return sum((cnt[c] - n * FREK_ID[c]) ** 2 / (n * FREK_ID[c]) for c in A)


# ---------------- Caesar ----------------
def caesar_enc(teks, k):
    return geser(teks, k)


def caesar_auto_crack(cipher):
    kandidat = [(chi_square(geser(cipher, -k)), k) for k in range(26)]
    kandidat.sort()
    return kandidat[0][1], kandidat


# ---------------- Vigenere ----------------
def vig_enc(teks, key):
    out, i = [], 0
    for c in teks:
        if c in A:
            out.append(A[(A.index(c) + A.index(key[i % len(key)])) % 26]); i += 1
        else:
            out.append(c)
    return "".join(out)


def vig_dec(teks, key):
    out, i = [], 0
    for c in teks:
        if c in A:
            out.append(A[(A.index(c) - A.index(key[i % len(key)])) % 26]); i += 1
        else:
            out.append(c)
    return "".join(out)


def ic(huruf):
    n = len(huruf)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in Counter(huruf).values()) / (n * (n - 1))


def tebak_panjang_key(cipher, maks=10):
    huruf = [c for c in cipher if c in A]
    hasil = []
    for L in range(1, maks + 1):
        kolom = ["".join(huruf[i::L]) for i in range(L)]
        hasil.append((L, sum(ic(k) for k in kolom) / L))
    # ambil panjang terkecil yang IC-nya hampir setara IC tertinggi
    # (kelipatan panjang key asli juga ber-IC tinggi, jadi pilih yang terkecil)
    puncak = max(v for _, v in hasil)
    for L, v in hasil:
        if v >= 0.9 * puncak:
            return L, hasil


def tebak_key(cipher, L):
    huruf = "".join(c for c in cipher if c in A)
    key = ""
    for i in range(L):
        kolom = huruf[i::L]
        k = min(range(26), key=lambda s: chi_square(geser(kolom, -s)))
        key += A[k]
    return key


if __name__ == "__main__":
    print("=== BAGIAN A: CAESAR AUTO-CRACK ===")
    c = caesar_enc("KEAMANAN SISTEM BERGANTUNG PADA KUNCI BUKAN PADA KERAHASIAAN ALGORITMA", 11)
    print("Ciphertext :", c)
    k, ranking = caesar_auto_crack(c)
    for skor, s in ranking[:3]:
        print(f"  shift={s:2d} skor chi-square={skor:8.1f}")
    print("Shift tebakan:", k, "->", geser(c, -k))

    print("\n=== BAGIAN B: VIGENERE ===")
    PLAIN = (
        "PENGAMANAN DATA PADA SEBUAH APLIKASI TIDAK CUKUP HANYA DENGAN MENGUBAH TEKS MENJADI "
        "ACAKAN KARENA PENYERANG DAPAT MEMANFAATKAN POLA PADA HASIL ENKRIPSI SEORANG PROGRAMER "
        "HARUS MEMAHAMI KELEMAHAN SETIAP ALGORITMA SEBELUM MEMAKAINYA DI DUNIA NYATA SEBAB "
        "KUNCI YANG PENDEK DAN BERULANG AKAN MENINGGALKAN JEJAK STATISTIK YANG MUDAH DIBACA "
        "OLEH SIAPA SAJA YANG MAU MENGANALISIS PESAN TERSEBUT DENGAN SABAR DAN TELITI"
    )
    KEY = "KOPI"
    cipher = vig_enc(PLAIN, KEY)
    print("Ciphertext :", cipher[:60], "...")
    print(f"IC teks asli (huruf saja): {ic([x for x in PLAIN if x in A]):.4f}")
    print(f"IC ciphertext            : {ic([x for x in cipher if x in A]):.4f}")
    L, tabel = tebak_panjang_key(cipher)
    print("IC rata-rata per panjang key:")
    for l, v in tabel:
        print(f"  L={l:2d} -> {v:.4f}" + ("   <== dipilih" if l == L else ""))
    key_tebakan = tebak_key(cipher, L)
    print("Key tebakan:", key_tebakan)
    print("Hasil dekripsi:", vig_dec(cipher, key_tebakan)[:70], "...")
    print("Berhasil?", vig_dec(cipher, key_tebakan) == PLAIN)
