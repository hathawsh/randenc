
import os
import shutil
import tempfile

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class TestKeyWriter(unittest.TestCase):

    def setUp(self):
        self.dirpath = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dirpath)

    def _class(self):
        from randenc.keys import KeyWriter
        return KeyWriter

    def _make(self, *args, **kw):
        return self._class()(*args, **kw)

    def _make_default(self, **kw):
        return self._make(self.dirpath, **kw)

    def test_get_fresh_key_first_time(self):
        obj = self._make_default()
        key_id, key = obj.get_fresh_key()
        self.assertIsInstance(key_id, bytes)
        self.assertEqual(len(key_id), 6)
        self.assertEqual(len(key), 48)
        self.assertIsInstance(key, bytes)
        f = open(os.path.join(self.dirpath, key_id.decode('ascii')))
        stored_key = f.read()
        f.close()
        self.assertEqual(key, stored_key)

    def test_get_fresh_key_second_time_matches_first(self):
        obj = self._make_default()
        key_id1, key1 = obj.get_fresh_key()
        key_id2, key2 = obj.get_fresh_key()
        self.assertEqual(key_id1, key_id2)
        self.assertEqual(key1, key2)

    def test_get_fresh_key_after_freshness_expired(self):
        obj = self._make_default(freshness=0)
        key_id1, key1 = obj.get_fresh_key()
        key_id2, key2 = obj.get_fresh_key()
        self.assertNotEqual(key_id1, key_id2)
        self.assertNotEqual(key1, key2)

    def test_prune(self):
        obj = self._make_default(max_age=0)
        self.assertEqual(os.listdir(self.dirpath), [])
        key_id, _key = obj.get_fresh_key()
        self.assertEqual(os.listdir(self.dirpath), [key_id.decode('ascii')])
        f = open(os.path.join(self.dirpath, '.hidden-file'), 'w')
        f.write(b'x')
        f.close()
        obj._prune()
        self.assertEqual(os.listdir(self.dirpath), ['.hidden-file'])


class TestKeyReader(unittest.TestCase):

    def setUp(self):
        self.dirpath = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dirpath)

    def _class(self):
        from randenc.keys import KeyReader
        return KeyReader

    def _make(self, *args, **kw):
        return self._class()(*args, **kw)

    def _make_default(self, **kw):
        return self._make(self.dirpath, **kw)

    def test_get_key_with_unicode(self):
        obj = self._make_default()
        with self.assertRaises(TypeError):
            obj.get_key(u"spam")

    def test_get_key_when_key_id_starts_with_dot(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'.spam')

    def test_get_key_when_key_id_contains_slash(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'spam/eggs')

    def test_get_key_when_key_id_contains_backslash(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'spam\\eggs')

    def test_get_key_when_key_id_does_not_exist(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'spam')

    def test_get_key_when_key_id_is_old(self):
        obj = self._make_default(max_age=0)
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 48)
        f.close()
        with self.assertRaises(KeyError):
            obj.get_key(b'mykey')

    def test_get_key_when_key_id_is_fresh(self):
        obj = self._make_default()
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 48)
        f.close()
        key = obj.get_key(b'mykey')
        self.assertEqual(key, b'x' * 48)

    def test_get_key_from_cache_when_key_id_is_fresh(self):
        obj = self._make_default()
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 48)
        f.close()
        key1 = obj.get_key(b'mykey')
        key2 = obj.get_key(b'mykey')
        self.assertEqual(key1, b'x' * 48)
        self.assertEqual(key2, b'x' * 48)

    def test_get_key_from_cache_when_key_id_is_old(self):
        obj = self._make_default()
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 48)
        f.close()
        obj.get_key(b'mykey')
        obj.max_age = 0
        with self.assertRaises(KeyError):
            obj.get_key(b'mykey')
        self.assertFalse(obj.keys)
