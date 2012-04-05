
The randenc package provides simple symmetric message encryption and
decryption functions with message packing, compression, cryptographic
hashes, and automatically rotated random keys.  It is designed for
short messages such as user ID tokens and browser cookies.  Usage
example::

    >>> from randenc import RandomEncryption
    >>> import tempfile
    >>> enc = RandomEncryption(tempfile.mkdtemp())
    >>> code = enc.encrypt({u'message': u'Hello, world!'})
    >>> len(code)
    107
    >>> enc.decrypt(code)
    {u'message': u'Hello, world!'}

The encryption key and signing key are produced automatically (using
os.urandom) and stored in the key directory.  Each key will be deleted
after one hour by default, invalidating all encrypted codes associated
with that key.

The encrypt function packs the content using msgpack, compresses it using
zlib (unless the compressed version is larger than than the uncompressed
version), encrypts it using AES-128 (since AES-128 seems to be considered
more secure than AES-256), signs it using HMAC over SHA-256, and encodes
in URL-safe base 64 format.  The decrypt function reverses that operation.
If the code fails validation or has expired, the decrypt function raises
DecryptionError.

This package is designed to be compatible with clusters.  The
keys may be stored on a shared volume using NFS or a FUSE-based filesystem.
With a little work, the keys could be stored in a key-value store such
as MongoDB.
