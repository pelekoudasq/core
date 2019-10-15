from hashlib import sha256

hash_nums = lambda *nums: sha256((''.join('%x:' % _ for _ in nums)).encode()).digest()
hash_texts = lambda *texts: sha256(('\x00'.join(texts)).encode()).digest()
