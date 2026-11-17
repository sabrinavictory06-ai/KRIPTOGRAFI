import base64
import hashlib
import os

USERS = {"dina": "kopi2024", "raka": "qwerty", "sari": "bandung!1"}
WORDLIST = ["123456", "password", "qwerty", "kopi2024", "indonesia", "admin"]


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def bit_diff(hex_a: str, hex_b: str) -> int:
    """Jumlah bit yang berbeda antara dua hash heksadesimal."""
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


def audit_base64():
    print("[1] BASE64 -> hanya encoding, bisa dibalik tanpa kunci")
    leaked = {u: base64.b64encode(p.encode()).decode() for u, p in USERS.items()}
    for user, enc in leaked.items():
        print(f"    {user:5s} {enc:16s} -> {base64.b64decode(enc).decode()}")


def audit_sha256_dictionary():
    print("\n[2] SHA-256 tanpa salt -> tidak bisa dibalik, tapi bisa ditebak")
    leaked = {u: sha256_hex(p) for u, p in USERS.items()}
    lookup = {sha256_hex(w): w for w in WORDLIST}  # rainbow table mini
    for user, digest in leaked.items():
        hasil = lookup.get(digest, "(tidak ada di wordlist)")
        print(f"    {user:5s} {digest[:16]}... -> {hasil}")


def audit_avalanche():
    print("\n[3] Avalanche effect: ubah 1 karakter password")
    a, b = sha256_hex("kopi2024"), sha256_hex("kopi2025")
    print(f"    kopi2024 -> {a[:24]}...")
    print(f"    kopi2025 -> {b[:24]}...")
    print(f"    Bit berbeda: {bit_diff(a, b)} dari 256 ({bit_diff(a, b) / 256:.0%})")


def audit_salted_pbkdf2():
    print("\n[4] PBKDF2 + salt acak -> password sama, hash berbeda")
    for i in (1, 2):
        salt = os.urandom(8)
        dk = hashlib.pbkdf2_hmac("sha256", b"kopi2024", salt, 100_000)
        print(f"    user{i}: salt={salt.hex()} hash={dk.hex()[:24]}...")


if __name__ == "__main__":
    audit_base64()
    audit_sha256_dictionary()
    audit_avalanche()
    audit_salted_pbkdf2()
