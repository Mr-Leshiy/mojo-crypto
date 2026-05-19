from .cipher import cipher, decipher


def cipher_128(
    input: InlineArray[UInt8, 16], key: InlineArray[UInt8, 16]
) -> InlineArray[UInt8, 16]:
    comptime Nk: Int = 4
    comptime Nr: Int = 10
    return cipher[Nr, Nk](input, key)


def cipher_192(
    input: InlineArray[UInt8, 16], key: InlineArray[UInt8, 24]
) -> InlineArray[UInt8, 16]:
    comptime Nk: Int = 6
    comptime Nr: Int = 12
    return cipher[Nr, Nk](input, key)


def cipher_256(
    input: InlineArray[UInt8, 16], key: InlineArray[UInt8, 32]
) -> InlineArray[UInt8, 16]:
    comptime Nk: Int = 8
    comptime Nr: Int = 14
    return cipher[Nr, Nk](input, key)


def decipher_128(
    input: InlineArray[UInt8, 16], key: InlineArray[UInt8, 16]
) -> InlineArray[UInt8, 16]:
    comptime Nk: Int = 4
    comptime Nr: Int = 10
    return decipher[Nr, Nk](input, key)
