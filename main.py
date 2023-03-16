import numpy as np


class GostCrypt:
    __slots__ = {
        '__key',
        '__s_box',
        '__sub_keys'
    }

    def __init__(self, key, s_box):
        self.key = key
        if np.shape(s_box) != (8, 16):
            raise ValueError(f'Incorrect shape of s_box {np.shape(s_box)}. It should be (8, 16)')
        self.s_box = s_box

    @property
    def key(self):
        return self.__key

    @property
    def sub_keys(self):
        return self.__sub_keys

    @key.setter
    def key(self, key):
        self.__key = key
        self.__sub_keys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]

    @property
    def s_box(self):
        return self.__s_box

    @s_box.setter
    def s_box(self, s_box):
        self.__s_box = s_box

    def _main_step(self, left, right, key):
        """The main step in the algorithm"""
        # step 1: addition with the key
        right_xor_key = np.bitwise_xor(right, key)
        result = np.uint32(0)
        # step 2: block-by-block replacement
        for i in range(8):
            result |= self.s_box[i][(right_xor_key >> (i * 4)) & 0b1111] << i * 4
        # step 3: cyclic shift by 11 bits to the left
        result = np.uint32(((result >> (32 - 11)) | result << 11) & 0xFFFFFFFF)
        # step 4: bitwise addition mod 2, so xor
        left ^= result
        # step 5: swap places
        return right, left

    def encrypt(self, msg):
        """Encrypt 64 bits of information"""
        if len(np.binary_repr(msg)) > 64:
            raise ValueError(f"Incorrect count of bits in the msg {len(msg)}. It shouldn't be more than 64")
        # the msg is devided into two parts of 128 bits each (left, right)
        left = np.uint32(np.right_shift(msg, np.uint8(32)))
        right = np.uint32(np.bitwise_and(msg, np.uint32(0xFFFFFFFF)))
        # 32 rounds with its keys
        # keys K1:K24 are cyclic K1:K8 keys
        for i in range(24):
            left, right = self._main_step(left, right, self.sub_keys[i % 8])
        # keys K25:K32 are K1:K8 keys going in reverse order
        for i in range(7, -1, -1):
            left, right = self._main_step(left, right, self.sub_keys[i])
        # merging the halves
        return right << np.uint64(32) | left

    def decrypt(self, msg):
        """Decrypt 64 bits of information"""
        if len(np.binary_repr(msg)) > 64:
            raise ValueError(f"Incorrect count of bits in the msg {len(msg)}. It shouldn't be more than 64")

        # the msg is devided into two parts of 128 bits each (left, right)
        left = np.uint32(np.right_shift(msg, np.uint8(32)))
        right = np.uint32(np.bitwise_and(msg, np.uint32(0xFFFFFFFF)))
        # same as encrypt function but the order of keys is inverted
        for i in range(8):
            left, right = self._main_step(left, right, self.sub_keys[i])

        for i in range(23, -1, -1):
            left, right = self._main_step(left, right, self.sub_keys[i % 8])

        return right << np.uint64(32) | left


def main():
    # 256-bits key
    key = 18935298755622895635870235193289930725652138058932089955432097650362872300295
    print(len(bin(key)))
    # replacement table Hij, where 0 <= i <= 7, 0 <= j <= 15, 0 <= Hij <= 15
    s_box = (
        (13, 5, 2, 8, 12, 10, 6, 13, 2, 1, 13, 14, 1, 1, 6, 13),
        (1, 1, 3, 2, 8, 10, 15, 14, 6, 13, 8, 1, 10, 7, 8, 19),
        (1, 5, 2, 1, 14, 2, 2, 3, 4, 15, 12, 6, 7, 1, 8, 13),
        (8, 3, 1, 0, 1, 7, 8, 12, 4, 6, 5, 1, 10, 4, 6, 5),
        (7, 2, 13, 10, 15, 10, 12, 7, 0, 0, 8, 11, 10, 5, 11, 13),
        (3, 1, 1, 2, 3, 3, 2, 11, 5, 2, 3, 6, 7, 10, 12, 4),
        (14, 15, 13, 10, 3, 5, 1, 8, 5, 4, 13, 4, 9, 8, 9, 13),
        (8, 14, 10, 7, 13, 14, 1, 5, 9, 5, 13, 10, 15, 1, 7, 15),
    )

    gost = GostCrypt(key, s_box)
    # 64-bits data
    data = 0xE0F2023FF2023FEE
    crypted_data = gost.encrypt(data)
    encrypted_data = gost.decrypt(crypted_data)
    print(data)
    print(encrypted_data)
    print(data == encrypted_data)


if __name__ == "__main__":
    main()
