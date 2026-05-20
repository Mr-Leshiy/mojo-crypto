from .cipher import cipher, decipher
from .expand import key_expansion
from .common import Nb


struct Aes[KeySize: Int]:
    comptime Nk: Int = Self.KeySize // 4
    comptime Nr: Int = Self.Nk + 6
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var w: InlineArray[UInt32, Self.WordsSize]

    def __init__(out self, key: InlineArray[UInt8, Self.KeySize]):
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"

        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)

    def encrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return cipher[Nr=Self.Nr](input, self.w)

    def decrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return decipher[Nr=Self.Nr](input, self.w)


comptime Aes128 = Aes[16]
comptime Aes192 = Aes[24]
comptime Aes256 = Aes[32]
