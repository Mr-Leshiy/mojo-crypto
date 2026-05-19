from .cipher import cipher, decipher
from .expand import key_expansion
from .common import Nb


struct Aes128:
    comptime Nk: Int = 4
    comptime Nr: Int = 10
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var w: InlineArray[UInt32, Self.WordsSize]

    def __init__(out self, key: InlineArray[UInt8, 16]):
        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)

    def encrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return cipher[Nr=Self.Nr](input, self.w)

    def decrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return decipher[Nr=Self.Nr](input, self.w)


struct Aes192:
    comptime Nk: Int = 6
    comptime Nr: Int = 12
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var w: InlineArray[UInt32, Self.WordsSize]

    def __init__(out self, key: InlineArray[UInt8, 24]):
        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)

    def encrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return cipher[Nr=Self.Nr](input, self.w)

    def decrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return decipher[Nr=Self.Nr](input, self.w)


struct Aes256:
    comptime Nk: Int = 8
    comptime Nr: Int = 14
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var w: InlineArray[UInt32, Self.WordsSize]

    def __init__(out self, key: InlineArray[UInt8, 32]):
        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)

    def encrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return cipher[Nr=Self.Nr](input, self.w)

    def decrypt(self, input: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
        return decipher[Nr=Self.Nr](input, self.w)
