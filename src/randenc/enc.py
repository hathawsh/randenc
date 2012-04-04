
from Crypto.Cipher import AES
from base64 import urlsafe_b64decode
from base64 import urlsafe_b64encode
import hashlib
import hmac
import msgpack
import os
import zlib


class DecryptionError(Exception):
    """Decryption failed."""


class Encryptor(object):
    """Pack, compress, encrypt, sign, and base-64 encode objects.
    """

    def __init__(self, key_writer):
        self.key_writer = key_writer

    def b64encode(self, s):
        """Convert bytes to an URL-safe base64 encoded string."""
        return urlsafe_b64encode(s).split('=', 1)[0].decode('ascii')

    def __call__(self, data, always_compress=False, compress_level=6):
        """Encrypt, sign, and base64 encode an object.

        The object must be compatible with msgpack, which generally
        means JSON compatible.
        """
        packed = msgpack.dumps(data)
        compressed = zlib.compress(packed, compress_level)
        if always_compress or len(compressed) <= len(packed):
            unencrypted = b'\x01' + compressed
        else:
            unencrypted = b'\x00' + packed

        iv = os.urandom(16)
        key_id, key = self.key_writer.get_fresh_key()
        hmac_key = key[:32]
        aes_key = key[32:]
        aes = AES.new(aes_key, AES.MODE_CFB, iv)  # @UndefinedVariable
        encrypted = aes.encrypt(unencrypted)
        to_sign = iv + encrypted
        signature = hmac.new(hmac_key, to_sign, hashlib.sha256).digest()
        to_encode = b''.join([b'\x00', key_id, b'\x00', signature, to_sign])
        return self.b64encode(to_encode)


class Decryptor(object):
    """Decrypt objects encrypted by Encryptor.

    yasso.resource uses this to read and verify access tokens.
    """

    def __init__(self, key_reader):
        self.key_reader = key_reader

    def b64decode(self, s):
        """Convert an URL-safe base64 encoded string to bytes."""
        if not isinstance(s, bytes):
            s = s.encode('ascii')
        pad_chars = (4 - len(s)) % 4
        to_decode = s + b'=' * pad_chars
        try:
            return urlsafe_b64decode(to_decode)
        except TypeError, e:
            raise DecryptionError('{0}'.format(e))

    def __call__(self, s):
        """Decrypt an object."""
        data = self.b64decode(s)
        if data[0] != b'\x00':
            raise DecryptionError("Unknown format")
        pos = data.find(b'\x00', 1)
        if pos < 1:
            raise DecryptionError("key_id missing from input")
        key_id = data[1:pos]
        try:
            key = self.key_reader.get_key(key_id)
        except KeyError:
            raise DecryptionError(
                "Key not found or expired: %s" % repr(key_id))

        hmac_key = key[:32]
        aes_key = key[32:]
        signature = data[pos + 1:pos + 33]
        signed = data[pos + 33:]
        h = hmac.new(hmac_key, signed, hashlib.sha256).digest()
        if not uniform_time_equal(h, signature):
            raise DecryptionError("Signature mismatch")

        iv = signed[:16]
        encrypted = signed[16:]
        aes = AES.new(aes_key, AES.MODE_CFB, iv)  # @UndefinedVariable
        unencrypted = aes.decrypt(encrypted)
        compressor = ord(unencrypted[0])
        if compressor == 0:
            packed = unencrypted[1:]
        elif compressor == 1:
            packed = zlib.decompress(unencrypted[1:])
        else:
            raise DecryptionError("Compressor unknown: {0}".format(compressor))

        return msgpack.loads(packed, use_list=True, encoding='utf-8')


def uniform_time_equal(a, b):
    """Compare two strings in uniform time to defeat timing attacks.
    """
    len_a = len(a)
    if len_a != len(b):
        return False

    diff = 0
    same = 0
    for a0, b0 in zip(a, b):
        # Note that it is possible that adding 0 takes a slightly
        # different amount of time than adding 1.  To ensure each
        # character is processed in exactly the same amount of time, each
        # loop iteration adds both 0 and 1, but to different accumulators
        # depending on the characters.
        diff += (a0 != b0)
        same += (a0 == b0)

    # Use both the 'diff' and 'same' variables to ensure neither gets
    # optimized away by a compiler.
    return diff == 0 and same == len_a
