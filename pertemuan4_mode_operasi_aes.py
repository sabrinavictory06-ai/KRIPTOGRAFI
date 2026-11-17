
from collections import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

KEY = get_random_bytes(16)
BS = 16


def blocks(data):
    return [data[i:i + BS] for i in range(0, len(data), BS)]


def enc_ecb(data):
    return AES.new(KEY, AES.MODE_ECB).encrypt(pad(data, BS))


def enc_cbc(data):
    iv = get_random_bytes(BS)
    return AES.new(KEY, AES.MODE_CBC, iv).encrypt(pad(data, BS))


def enc_ctr(data):
    return AES.new(KEY, AES.MODE_CTR).encrypt(data)  # nonce acak otomatis


def laporan_duplikat(nama, ct):
    b = blocks(ct)
    dup = sum(c - 1 for c in Counter(b).values() if c > 1)
    print(f"  {nama:4s}: {len(b):3d} blok, {len(set(b)):3d} unik, {dup:3d} blok duplikat")


def eksperimen_tabel():
    status = ["LUNAS", "LUNAS", "BELUM", "LUNAS", "BELUM", "LUNAS", "LUNAS", "LUNAS"]
    data = b"".join(f"STATUS={s}".ljust(BS).encode() for s in status)
    print("Eksperimen 1: 8 record, tiap record tepat 1 blok")
    for nama, f in [("ECB", enc_ecb), ("CBC", enc_cbc), ("CTR", enc_ctr)]:
        laporan_duplikat(nama, f(data))
    ecb = blocks(enc_ecb(data))[:8]
    print("  Penyerang hanya melihat ECB, tetapi bisa mengelompokkan record:")
    peta, hasil = {}, []
    for blk in ecb:
        peta.setdefault(blk, "ABCDEFGH"[len(peta)])
        hasil.append(peta[blk])
    print("  Pola blok ->", " ".join(hasil), "  (asli:", " ".join(s[0] for s in status) + ")")


HURUF = {
    "B": ["###.", "#..#", "###.", "#..#", "###."],
    "O": [".##.", "#..#", "#..#", "#..#", ".##."],
    "C": [".###", "#...", "#...", "#...", ".###"],
    "R": ["###.", "#..#", "###.", "#.#.", "#..#"],
}


def buat_gambar(kata="BOCOR"):
    baris = ["" for _ in range(5)]
    for ch in kata:
        for i in range(5):
            baris[i] += HURUF[ch][i] + "."
    return baris


def eksperimen_gambar():
    gambar = buat_gambar()
    data = b"".join(
        (b"\xff" if p == "#" else b"\x00") * BS for row in gambar for p in row
    )
    lebar = len(gambar[0])
    simbol = ".:-=+*#%@"

    def render(ct, acak=False):
        bl = blocks(ct)[: len(data) // BS]
        peta = {}
        for b in bl:
            peta.setdefault(b, simbol[b[0] % 9] if acak else simbol[len(peta) % 9])
        for r in range(5):
            print("   ", "".join(peta[bl[r * lebar + c]] for c in range(lebar)))
        return len(peta)

    print("\nEksperimen 2: gambar kata 'BOCOR' (1 piksel = 1 blok)")
    print("  Gambar asli:")
    for row in gambar:
        print("   ", row.replace("#", "█").replace(".", " "))
    print("  Ciphertext ECB (blok sama -> simbol sama):")
    n1 = render(enc_ecb(data))
    print(f"  -> {n1} blok unik, bentuk gambar masih terbaca")
    print("  Ciphertext CBC:")
    n2 = render(enc_cbc(data), acak=True)
    print(f"  -> {n2} blok unik, bentuk gambar hilang")


if __name__ == "__main__":
    eksperimen_tabel()
    eksperimen_gambar()
