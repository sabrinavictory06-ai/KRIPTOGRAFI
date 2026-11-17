import os
import unittest
from dataclasses import replace

import filesafe as fs

alice, bob, carol, mallory = (fs.Pengguna(n) for n in ("Alice", "Bob", "Carol", "Mallory"))


def siapkan():
    k_alice, k_bob, k_carol = fs.Kontak(), fs.Kontak(), fs.Kontak()
    k_alice.pin(bob.pub_bytes, bob.fingerprint)
    for k in (k_bob, k_carol):
        k.pin(alice.pub_bytes, alice.fingerprint)
    data = os.urandom(3000)
    paket = fs.kirim(alice, k_alice.ambil(bob.fingerprint), bob.fingerprint, data)
    return k_bob, k_carol, data, paket


def ditolak(testcase, kode, fn):
    with testcase.assertRaises(fs.Ditolak) as c:
        fn()
    testcase.assertEqual(c.exception.kode, kode)


class UjiFileSafe(unittest.TestCase):
    def test_1_normal(self):
        k_bob, _, data, p = siapkan()
        self.assertEqual(fs.terima(bob, k_bob, set(), p), data)

    def test_2_cloud_tidak_bisa_membaca(self):
        k_bob, _, _, _ = siapkan()
        rahasia = b"KATA-RAHASIA" * 50
        p = fs.kirim(alice, bob.pub, bob.fingerprint, rahasia)
        self.assertNotIn(b"KATA-RAHASIA", p.ciphertext)

    def test_3_ciphertext_diubah(self):
        k_bob, _, _, p = siapkan()
        b = bytearray(p.ciphertext); b[0] ^= 1
        ditolak(self, "TANDA_TANGAN_SALAH", lambda: fs.terima(bob, k_bob, set(), replace(p, ciphertext=bytes(b))))

    def test_4_kunci_terbungkus_diganti(self):
        k_bob, _, _, p = siapkan()
        ditolak(self, "TANDA_TANGAN_SALAH", lambda: fs.terima(bob, k_bob, set(), replace(p, enc_key=os.urandom(256))))

    def test_5_mitm_saat_pairing(self):
        k = fs.Kontak()   # Mallory menyodorkan kunci miliknya, fingerprint Bob dari tatap muka
        ditolak(self, "FINGERPRINT_BEDA", lambda: k.pin(mallory.pub_bytes, bob.fingerprint))

    def test_6_mallory_membuat_paket_sendiri(self):
        k_bob, _, _, _ = siapkan()
        palsu = fs.kirim(mallory, bob.pub, bob.fingerprint, b"malware")
        ditolak(self, "PENGIRIM_TIDAK_DIKENAL", lambda: fs.terima(bob, k_bob, set(), palsu))
        menyamar = replace(palsu, pengirim_fp=alice.fingerprint)
        ditolak(self, "TANDA_TANGAN_SALAH", lambda: fs.terima(bob, k_bob, set(), menyamar))

    def test_7_paket_dialihkan_ke_carol(self):
        _, k_carol, _, p = siapkan()
        ditolak(self, "BUKAN_UNTUK_SAYA", lambda: fs.terima(carol, k_carol, set(), p))

    def test_8_paket_diulang(self):
        k_bob, _, _, p = siapkan()
        dilihat = set()
        fs.terima(bob, k_bob, dilihat, p)
        ditolak(self, "PAKET_DIULANG", lambda: fs.terima(bob, k_bob, dilihat, p))

    def test_9_BATAS_salah_pin_membuka_jalan_mitm(self):
        """Jika Alice me-pin kunci Mallory tanpa cek fingerprint, Mallory bisa membaca file."""
        k_ceroboh = fs.Kontak(); k_ceroboh.pin(mallory.pub_bytes, mallory.fingerprint)
        p = fs.kirim(alice, k_ceroboh.ambil(mallory.fingerprint), mallory.fingerprint, b"rahasia")
        k_m = fs.Kontak(); k_m.pin(alice.pub_bytes, alice.fingerprint)
        self.assertEqual(fs.terima(mallory, k_m, set(), p), b"rahasia")


if __name__ == "__main__":
    unittest.main(verbosity=2)
