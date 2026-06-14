from sys import abort

comptime BLOCK_SIZE: Int = 16
comptime KEY_SIZE: Int = 16
comptime TAG_SIZE: Int = 16


struct FieldElement(InlineArray[UInt8, BLOCK_SIZE]):
    pass
