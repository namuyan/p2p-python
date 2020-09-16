from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.curves import SECP256k1
from collections import deque
from typing import Deque, Iterator
from hashlib import sha256
from io import BytesIO
import logging


log = logging.getLogger(__name__)

# static params (don't change after)
BITMAP_LEN = 256  # bytes
THRESHOLD = 252  # 1.1%
FP_LIMIT = 0.0005  # 0.05%


class BloomFilter(object):
    """
    scalable bloom filter

    * designed false-positive rate 1% when insert 2000 keys
    * one bitmap int can contain 100 keys and max 10000 keys
    * throw away old bitmaps if over filled filter length
    """

    def __init__(self) -> None:
        self.pre = 0b0
        # order by old to new
        self.filled: Deque[int] = deque(maxlen=99)

    def __repr__(self) -> str:
        size = len(self) * BITMAP_LEN / 1000
        maxsize = (self.filled.maxlen + 1) * BITMAP_LEN / 1000
        return f"<BloomFilter fp={self.false_positive():.2%} size={size:.2f}/{maxsize:.2f}kb>"

    def __len__(self) -> int:
        """number of bloom filters"""
        return 1 + len(self.filled)

    def export(self, io: BytesIO) -> None:
        """export as binary format"""
        io.write(self.pre.to_bytes(BITMAP_LEN, "big"))
        io.write(len(self.filled).to_bytes(4, "big"))
        for bitmap in self.filled:
            io.write(bitmap.to_bytes(BITMAP_LEN, "big"))

    @classmethod
    def restore(cls, io: BytesIO) -> 'BloomFilter':
        """restore from exported binary"""
        bloom = BloomFilter()
        bloom.pre = int.from_bytes(io.read(BITMAP_LEN), "big")
        length = int.from_bytes(io.read(4), "big")
        for _ in range(length):
            bloom.filled.append(int.from_bytes(io.read(BITMAP_LEN), "big"))
        return bloom

    def add(self, key: VerifyingKey) -> None:
        """add new key to filter"""
        bitmap = get_hash(key)
        if self._check(bitmap):
            return
        # not found the key
        self.pre |= bitmap
        if FP_LIMIT < false_positive(self.pre):
            self.filled.append(self.pre)
            self.pre = 0b0

    def check(self, key: VerifyingKey) -> bool:
        """check the key exist"""
        bitmap = get_hash(key)
        return self._check(bitmap)

    def _check(self, bitmap: int) -> bool:
        """check the bitmap contain"""
        if (self.pre | bitmap) == self.pre:
            return True
        for bloom in self.filled:
            if (bloom | bitmap) == bloom:
                return True
        return False

    def marge_filter(self, bloom: 'BloomFilter') -> None:
        """marge another bloom filter"""
        assert false_positive(bloom.pre) < FP_LIMIT, ("pre-filter is bad", bloom)

        new_rate = false_positive(self.pre | bloom.pre)
        if FP_LIMIT < new_rate:
            self.filled.append(bloom.pre)
        else:
            self.pre |= bloom.pre

        for bitmap in bloom.filled:
            if FP_LIMIT * 2 < false_positive(bitmap):
                log.debug("ignore bad bitmap")
                continue
            if bitmap in self.filled:
                continue
            if self.filled.maxlen <= len(self.filled):
                continue  # ignore overflowed bitmap
            # add as oldest bitmap
            self.filled.insert(0, bitmap)

    def false_positive(self) -> float:
        """false-positive rate of all filter"""
        rate = 1.0 - false_positive(self.pre)
        for bloom in self.filled:
            rate *= 1.0 - false_positive(bloom)
        return 1.0 - rate


def false_positive(bitmap: int) -> float:
    """false-positive rate of bitmap"""
    count = BITMAP_LEN * 8  # number of zero bit
    count -= bin(bitmap).count("1")
    zero_rate = THRESHOLD / 255
    return pow(zero_rate, count)


def get_hash_iter(key: bytes) -> Iterator[int]:
    """return 0~255 int forever"""
    while True:
        key = sha256(key).digest()
        for elm in key:
            yield elm


def get_hash(key: VerifyingKey) -> int:
    """worm-eaten like filter"""
    x_bytes = int(key.pubkey.point.x()).to_bytes(32, 'big')
    # note: No common standard in Bloom filter
    hash_iter = get_hash_iter(x_bytes)
    mask = 0b1
    hashed = 0b0
    for _ in range(BITMAP_LEN * 8):
        if THRESHOLD < next(hash_iter):
            hashed |= mask
        mask <<= 1
    return hashed


def test_bloom_filter() -> None:
    """check filter's quality params"""
    bloom = BloomFilter()
    print(1, len(bloom), bloom.false_positive()*100)
    keys = [SigningKey.generate(SECP256k1).verifying_key for _ in range(2000)]
    for key in keys:
        bloom.add(key)
    print(2, len(bloom), bloom.false_positive()*100)

    io = BytesIO()
    bloom.export(io)
    io.seek(0)
    new_bloom = BloomFilter.restore(io)
    assert new_bloom.pre == bloom.pre and new_bloom.filled == bloom.filled, (new_bloom, bloom)
    print(3, io.getbuffer().hex())

    fp = 0
    for _ in range(1000):
        if bloom.check(SigningKey.generate(SECP256k1).verifying_key):
            fp += 1
    print(4, fp, fp / 1000 * 100, "%")
    print(5, bloom)
    tp = 0
    for key in keys:
        if bloom.check(key):
            tp += 1
    assert tp == len(keys), (tp, len(keys))


__all__ = [
    "BloomFilter",
]
