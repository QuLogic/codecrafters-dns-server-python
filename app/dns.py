"""DNS packets."""

from __future__ import annotations

import dataclasses
import enum
import math
import typing


_TBF = typing.TypeVar('_TBF', bound='BitField')


def bit_field(width, **kwargs):
    """Create a bit field with given *width*."""
    return dataclasses.field(metadata={'width': width}, **kwargs)


def _check_bit_fields(obj, allow_non_bitfield: bool = True) -> None:
    for field in dataclasses.fields(obj):
        if 'width' not in field.metadata:
            if allow_non_bitfield:
                continue
            raise TypeError(f'{field.name} is not annotated with bit field width')
        max_value = 2 ** field.metadata['width'] - 1
        value = getattr(obj, field.name)
        if value < 0 or value > max_value:
            raise ValueError(
                f'{field.name} ({value}) is out of bounds [0, {max_value}]')


class BitField:
    """A mixin for dataclass of bit fields."""

    def __post_init__(self) -> None:
        """Validate fields fit within specified width."""
        _check_bit_fields(self, allow_non_bitfield=False)

    @classmethod
    @property
    def total_bytes(cls) -> int:
        """Calculate size of bitfield in bytes."""
        total_width = sum(field.metadata['width'] for field in dataclasses.fields(cls))
        return math.ceil(total_width / 8)

    @classmethod
    def unpack(cls: type[_TBF], buf: bytes) -> _TBF:
        """Unpack a bitfield out of a byte buffer."""
        if len(buf) < cls.total_bytes:
            raise ValueError(
                f'Buffer of length {len(buf)} is smaller than expected '
                f'bitfield size ({cls.total_bytes}).')

        result = {}
        index = 0
        temp_value = 0
        current_width = 0
        for field in dataclasses.fields(cls):
            width = field.metadata['width']

            # Grab enough data from the buffer for this field.
            while current_width < width:
                temp_value <<= 8
                temp_value |= buf[index]
                current_width += 8
                index += 1

            # Get this field's bits by shifting (and truncating) extra bits.
            result[field.name] = temp_value >> (current_width - width)

            # Calculate a mask with the remaining bits only.
            mask = 2 ** (current_width - width) - 1

            # Remove this field's bits from the temporary value.
            temp_value &= mask
            current_width -= width

        return cls(**result)

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


@dataclasses.dataclass(kw_only=True)
class Header(BitField):
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
    question_count: int = bit_field(16, default=0)
    answer_record_count: int = bit_field(16, default=0)
    authority_record_count: int = bit_field(16, default=0)
    additional_record_count: int = bit_field(16, default=0)


class QuestionType(enum.IntEnum):
    """
    QTYPE fields appear in the question part of a query.

    QTYPES are a superset of TYPEs, hence all TYPEs are valid QTYPEs.
    """

    A = 1  # A host address.
    NS = 2  # An authoritative name server.
    MD = 3  # A mail destination (Obsolete - use MX).
    MF = 4  # A mail forwarder (Obsolete - use MX).
    CNAME = 5  # The canonical name for an alias.
    SOA = 6  # Marks the start of a zone of authority.
    MB = 7  # A mailbox domain name (EXPERIMENTAL).
    MG = 8  # A mail group member (EXPERIMENTAL).
    MR = 9  # A mail rename domain name (EXPERIMENTAL).
    NULL = 10  # A null RR (EXPERIMENTAL).
    WKS = 11  # A well known service description.
    PTR = 12  # A domain name pointer.
    HINFO = 13  # Host information.
    MINFO = 14  # Mailbox or mail list information.
    MX = 15  # Mail exchange.
    TXT = 16  # Text strings.
    AXFR = 252  # A request for a transfer of an entire zone.
    MAILB = 253  # A request for mailbox-related records (MB, MG or MR).
    MAILA = 254  # A request for mail agent RRs (Obsolete - see MX).
    ALL = 255  # A request for all records.


class QuestionClass(enum.IntEnum):
    """
    QCLASS fields appear in the question section of a query.

    QCLASS values are a superset of CLASS values; every CLASS is a valid QCLASS.
    """

    IN = 1  # The Internet.
    CS = 2  # The CSNET class (Obsolete - used only for examples in some obsolete RFCs).
    CH = 3  # The CHAOS class.
    HS = 4  # Hesiod [Dyer 87].
    ALL = 255  # Any class.


@dataclasses.dataclass
class Question:
    """A DNS question."""

    name: tuple[bytes, ...]
    qtype: QuestionType = bit_field(16)
    qclass: QuestionClass = bit_field(16)

    def __post_init__(self):
        """Validate fields fit within question."""
        for name in self.name:
            if len(name) > 255:
                raise ValueError(
                    f'Name entry {name} cannot be longer than 255 characters')
        _check_bit_fields(self)

    @classmethod
    def unpack(cls, buf: bytes) -> tuple[Question, bytes]:
        """Unpack a question out of a byte buffer and return remaining bytes."""
        # TODO: Check buffer size.
        name = []
        while (size := buf[0]) != 0:
            # Add 1 everywhere to skip the size byte.
            label = buf[1:size + 1]
            buf = buf[size + 1:]
            name.append(label)
        # Add 1 to remaining indices to skip the last 0x00 size byte.
        qtype = QuestionType((buf[1] << 8) | buf[2])
        qclass = QuestionClass((buf[3] << 8) | buf[4])
        return cls(name=tuple(name), qtype=qtype, qclass=qclass), buf[5:]

    def pack(self) -> bytes:
        """Pack a question into a bytes object."""
        result = []
        for name in self.name:
            result += [len(name), *name]
        result += [
            0x00,
            self.qtype >> 8, self.qtype & 0xff,
            self.qclass >> 8, self.qclass & 0xff,
        ]
        return bytes(result)


@dataclasses.dataclass
class Packet:
    """A DNS packet."""

    header: Header
    questions: tuple[Question, ...] = ()

    auto_set_header: dataclasses.InitVar[bool] = False

    def __post_init__(self, auto_set_header: bool) -> None:
        """Refresh header fields if requested."""
        if auto_set_header:
            self.header = dataclasses.replace(
                self.header,
                question_count=len(self.questions),
            )

    @classmethod
    def unpack(cls, buf: bytes) -> Packet:
        """Unpack a DNS packet out of a byte buffer."""
        header = Header.unpack(buf)
        remaining = buf[Header.total_bytes:]

        questions = []
        for i in range(header.question_count):
            question, remaining = Question.unpack(remaining)
            questions.append(question)

        return cls(header=header, questions=tuple(questions))

    def pack(self) -> bytes:
        """Pack a DNS packet into a bytes object."""
        result = self.header.pack()
        for question in self.questions:
            result += question.pack()
        return result

    def print(self, indent_level=0, tab_size=4):
        """Print out a DNS packet at a given *indent_level* and *tab_size*."""
        tab = ' ' * tab_size
        initial = tab * indent_level
        print(f'{initial}{self.header}')

        for i, question in enumerate(self.questions):
            print(f'{initial}{tab}Question {i}: {question}')
