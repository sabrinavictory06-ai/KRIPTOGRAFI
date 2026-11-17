import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class Ditolak(Exception):
    def __init__(self, kode):
        super().__init__(kode)
        self.kode = kode


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:  # beri awalan panjang supaya batas antar-bagian tidak ambigu
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


class Pengguna:
    def __init__(self, nama):
        self.nama = nama
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub = self._priv.public_key()

    @property
    def pub_bytes(self):
        return self.pub.public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def fingerprint(self):  # dibacakan / dipindai tatap muka
        return hashlib.sha256(self.pub_bytes).digest()[:20]

    def tanda_tangan(self, data):
        return self._priv.sign(data, PSS, hashes.SHA256())

    def buka_kunci(self, enc_key):
        return self._priv.decrypt(enc_key, OAEP)


class Kontak:
    """Daftar kunci publik yang sudah dicocokkan fingerprint-nya (pinning)."""

    def __init__(self):
        self._daftar = {}

    def pin(self, pub_bytes, fingerprint_tatap_muka):
        if hashlib.sha256(pub_bytes).digest()[:20] != fingerprint_tatap_muka:
            raise Ditolak("FINGERPRINT_BEDA")
        self._daftar[fingerprint_tatap_muka] = serialization.load_der_public_key(pub_bytes)

    def ambil(self, fp):
        if fp not in self._daftar:
            raise Ditolak("PENGIRIM_TIDAK_DIKENAL")
        return self._daftar[fp]


@dataclass(frozen=True)
class Paket:
    file_id: bytes
    pengirim_fp: bytes
    penerima_fp: bytes
    nonce: bytes
    enc_key: bytes
    ciphertext: bytes
    tanda_tangan: bytes

    def isi_ditandatangani(self):
        return sha256(self.file_id, self.pengirim_fp, self.penerima_fp, self.nonce,
                      self.enc_key, hashlib.sha256(self.ciphertext).digest())


def kirim(pengirim: Pengguna, pub_penerima, fp_penerima: bytes, data: bytes) -> Paket:
    file_id, nonce, kunci = os.urandom(16), os.urandom(12), AESGCM.generate_key(256)
    aad = sha256(file_id, pengirim.fingerprint, fp_penerima)
    ciphertext = AESGCM(kunci).encrypt(nonce, data, aad)
    enc_key = pub_penerima.encrypt(kunci, OAEP)
    p = Paket(file_id, pengirim.fingerprint, fp_penerima, nonce, enc_key, ciphertext, b"")
    return Paket(**{**p.__dict__, "tanda_tangan": pengirim.tanda_tangan(p.isi_ditandatangani())})


def terima(penerima: Pengguna, kontak: Kontak, sudah_dilihat: set, p: Paket) -> bytes:
    if p.penerima_fp != penerima.fingerprint:
        raise Ditolak("BUKAN_UNTUK_SAYA")
    pub_pengirim = kontak.ambil(p.pengirim_fp)          # kunci dari daftar lokal, bukan dari cloud
    try:
        pub_pengirim.verify(p.tanda_tangan, p.isi_ditandatangani(), PSS, hashes.SHA256())
    except InvalidSignature:
        raise Ditolak("TANDA_TANGAN_SALAH")
    if p.file_id in sudah_dilihat:
        raise Ditolak("PAKET_DIULANG")
    try:
        kunci = penerima.buka_kunci(p.enc_key)
        data = AESGCM(kunci).decrypt(p.nonce, p.ciphertext,
                                     sha256(p.file_id, p.pengirim_fp, p.penerima_fp))
    except (InvalidTag, ValueError):
        raise Ditolak("DEKRIPSI_GAGAL")
    sudah_dilihat.add(p.file_id)                        
    return data


if __name__ == "__main__":
    alice, bob = Pengguna("Alice"), Pengguna("Bob")
    print("Fingerprint Bob:", bob.fingerprint.hex(" ", 2))
    k_alice, k_bob = Kontak(), Kontak()
    k_alice.pin(bob.pub_bytes, bob.fingerprint)
    k_bob.pin(alice.pub_bytes, alice.fingerprint)
    paket = kirim(alice, k_alice.ambil(bob.fingerprint), bob.fingerprint, b"Isi file rahasia")
    print("Bob menerima:", terima(bob, k_bob, set(), paket))
