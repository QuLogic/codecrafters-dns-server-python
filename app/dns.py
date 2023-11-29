"""DNS packets."""

import dataclasses


def bit_field(width, **kwargs):
    """Create a bit field with given *width*."""
    return dataclasses.field(metadata={'width': width}, **kwargs)


@dataclasses.dataclass(kw_only=True)
class DNSHeader:
    """A DNS header."""

    packet_identifier: int = bit_field(16)
    query_response: int = bit_field(1)
    operation_code: int = bit_field(4)
    authoritative_answer: int = bit_field(1)
    truncation: int = bit_field(1)
    recursion_desired: int = bit_field(1)
    recursion_available: int = bit_field(1)
    reserved: int = bit_field(3, default=0)
    response_code: int = bit_field(4)
    question_count: int = bit_field(16)
    answer_record_count: int = bit_field(16)
    authority_record_count: int = bit_field(16)
    additional_record_count: int = bit_field(16)

    def __post_init__(self) -> None:
        """Validate fields fit within specified width."""
        for field in dataclasses.fields(self):
            if 'width' not in field.metadata:
                raise TypeError(f'{field.name} is not annotated with bit field width')
            max_value = 2 ** field.metadata['width'] - 1
            value = getattr(self, field.name)
            if value < 0 or value > max_value:
                raise ValueError(
                    f'{field.name} ({value}) is out of bounds [0, {max_value}]')

    def pack(self) -> bytes:
        """
        Pack bit fields into a bytes object.

        Bit fields are packed in big endian order. If the total number of bits is not a
        multiple of 8, then the last byte will by filled with zeroes.
        """
        result = []
        value = 0
        current_width = 0
        for field in dataclasses.fields(self):
            width = field.metadata['width']
            bits = getattr(self, field.name)

            # Append this bit field to the current integer.
            value <<= width
            value |= bits
            current_width += width

            # When we have enough bits, turn them into bytes.
            # This is probably inefficient if we have a field that is many multiples of
            # 8 bits wide, but whatever.
            while current_width >= 8:
                current_byte = value >> (current_width - 8)  # Grab top 8 bits.
                current_width -= 8
                value &= 2**current_width - 1  # Mask out the top 8 bits.
                result.append(current_byte)

        if current_width > 0:
            current_byte = value << (8 - current_width)  # Shift final bits to MSB.
            result.append(current_byte)

        return bytes(result)
