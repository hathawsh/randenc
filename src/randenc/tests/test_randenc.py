
import shutil
import tempfile
from base64 import urlsafe_b64encode

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class TestRandomEncryption(unittest.TestCase):

    def setUp(self):
        self.dirpath = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dirpath)

    def _make_default(self):
        from randenc import RandomEncryption
        return RandomEncryption(self.dirpath)

    def test_encrypt_and_decrypt_without_compression(self):
        randenc = self._make_default()
        ciphertext = randenc.encrypt({'message': 'Hello, world!'})
        self.assertIsInstance(ciphertext, unicode)
        data = randenc.decrypt(ciphertext)
        self.assertLess(len(ciphertext), 120)
        self.assertEqual(data, {'message': 'Hello, world!'})

        # Encrypting again should not produce the same ciphertext.
        ciphertext2 = randenc.encrypt({'message': 'Hello, world!'})
        self.assertNotEqual(ciphertext, ciphertext2)

    def test_encrypt_and_decrypt_with_compression(self):
        randenc = self._make_default()
        ciphertext = randenc.encrypt('0' * 4000)
        self.assertIsInstance(ciphertext, unicode)
        # The content is easy to compress, so expect a relatively
        # small message.
        self.assertLess(len(ciphertext), 200)
        data = randenc.decrypt(ciphertext)
        self.assertEqual(data, '0' * 4000)

    def test_encrypt_and_decrypt_tiny(self):
        randenc = self._make_default()
        ciphertext = randenc.encrypt(3)
        self.assertIsInstance(ciphertext, unicode)
        data = randenc.decrypt(ciphertext)
        self.assertGreater(len(ciphertext), 70)
        self.assertLess(len(ciphertext), 90)
        self.assertEqual(data, 3)

    def test_decrypt_wrong_format(self):
        randenc = self._make_default()
        from randenc import DecryptionError
        with self.assertRaises(DecryptionError):
            randenc.decrypt('BBBB')

    def test_decrypt_missing_key_id(self):
        randenc = self._make_default()
        from randenc import DecryptionError
        with self.assertRaises(DecryptionError):
            randenc.decrypt(urlsafe_b64encode(b'\0spam'))

    def test_decrypt_with_signature_mismatch(self):
        randenc = self._make_default()
        ciphertext = randenc.encrypt({'message': 'Hello, world!'})
        data = randenc.decrypt.b64decode(ciphertext)
        data = data[:-1] + bytes([ord(data[-1]) ^ 16])
        broken_ciphertext = urlsafe_b64encode(data)
        from randenc import DecryptionError
        with self.assertRaises(DecryptionError):
            randenc.decrypt(broken_ciphertext)
