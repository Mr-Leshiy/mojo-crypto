comptime BLOCK_SIZE: Int = 16
comptime KEY_SIZE: Int = 16
comptime TAG_SIZE: Int = 16

# P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
comptime P1: UInt64 = 0xC200_0000_0000_0000
