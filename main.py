import numpy as np


class GostCrypt:
    __slots__ = {
        '__key',
        '__s_box'
    }

    def __init__(self, key=None, s_box=None):
        self.key = key
        self.s_box = s_box
        ...

    @property
    def key(self):
        return self.__key

    @key.setter
    def key(self, key):
        self.__key = key

    def s_box(self):
        return self.__s_box

    @s_box.setter
    def s_box(self, s_box):
        self.__s_box = s_box

    def encrypt(self):
        ...

    def decrypt(self):
        ...


def main():
    key = 18318279387912387912789378912379821879387978238793278872378329832982398023031
    s_box = (
        (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
        (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
        (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
        (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
        (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
        (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
        (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
        (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
    )
    gost = GostCrypt(key, s_box)


if __name__ == "__main__":
    main()
