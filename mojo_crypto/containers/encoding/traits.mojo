trait Decodable:
    def decode(self, s: String) raises -> List[UInt8]:
        ...

    def decode[SIZE: Int](self, s: String) raises -> InlineArray[UInt8, SIZE]:
        ...


trait Encodable:
    def encode[o: Origin](self, data: Span[UInt8, o]) raises -> String:
        ...
