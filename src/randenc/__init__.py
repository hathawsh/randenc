
from randenc.enc import DecryptionError
from randenc.enc import Decryptor
from randenc.enc import Encryptor
from randenc.keys import KeyReader
from randenc.keys import KeyWriter


class RandomEncryption(object):
    """Symmetric encryption using automatically rotated random keys.

    The encrypt function handles packing, compression, encryption,
    signing, and encoding in URL-safe base64 format.

    The decrypt function handles decoding, signature checking, decryption,
    decompression, and unpacking.
    """

    def __init__(self, dirpath,
            length=48,
            freshness=300,
            max_age=3600,
            max_future=300,
        ):

        self.dirpath = dirpath
        self.length = length
        self.freshness = freshness
        self.max_age = max_age
        self.max_future = max_future

        self.writer = KeyWriter(dirpath,
            length=length,
            freshness=freshness,
            max_age=max_age,
            max_future=max_future,
        )
        self.reader = KeyReader(dirpath,
            length=length,
            max_age=max_age,
            max_future=max_future,
        )

        self.encrypt = Encryptor(self.writer)
        self.decrypt = Decryptor(self.reader)

    @property
    def duration(self):
        """Return the minimum number of seconds codes should survive."""
        freshness = self.freshness
        return max(self.max_age - freshness, freshness)
