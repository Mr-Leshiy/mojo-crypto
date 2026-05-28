trait Decodable:
    def decode(self, s: String) raises -> List[UInt8]:
        ...


trait Encodable:
    def encode[o: Origin](self, data: Span[UInt8, o]) -> String:
        ...
