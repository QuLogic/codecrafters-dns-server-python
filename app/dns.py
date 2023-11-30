"""DNS packets."""

from __future__ import annotations

import dataclasses
import enum
import math
import re
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
    def unpack(cls: type[_TBF], buf: bytes, offset: int) -> tuple[_TBF, int]:
        """
        Unpack a bitfield out of a byte buffer.

        Parameters
        ----------
        buf
            The byte buffer to unpack.
        offset
            The offset in the byte buffer at which to start unpacking this struct.

        Returns
        -------
        bitfield
            The bit field struct.
        offset
            The offset of the next byte after this struct.
        """
        if len(buf[offset:]) < cls.total_bytes:
            raise ValueError(
                f'Buffer of length {len(buf) - offset} is smaller than expected '
                f'bitfield size ({cls.total_bytes})')

        result = {}
        temp_value = 0
        current_width = 0
        for field in dataclasses.fields(cls):
            width = field.metadata['width']

            # Grab enough data from the buffer for this field.
            while current_width < width:
                temp_value <<= 8
                temp_value |= buf[offset]
                current_width += 8
                offset += 1

            # Get this field's bits by shifting (and truncating) extra bits.
            result[field.name] = temp_value >> (current_width - width)

            # Calculate a mask with the remaining bits only.
            mask = 2 ** (current_width - width) - 1

            # Remove this field's bits from the temporary value.
            temp_value &= mask
            current_width -= width

        return cls(**result), offset

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


class LabelSequence(tuple[bytes, ...]):
    """A DNS label sequence."""

    def __new__(cls, *args):
        """Validate fields fit within label sequence."""
        self = super().__new__(cls, *args)
        for name in self:
            if len(name) > 63:
                raise ValueError(
                    f'Name entry {name!r} may not be longer than 63 characters')
            if not re.fullmatch(rb'[A-Za-z]([A-Za-z0-9-]*[A-Za-z])?', name):
                raise ValueError(f'Name entry {name!r} does not obey DNS rules')
        return self

    @classmethod
    def unpack(cls, buf: bytes, offset: int,
               other_offsets: set[int] | None = None) -> tuple[LabelSequence, int]:
        """
        Unpack a label sequence out of a byte buffer.

        Parameters
        ----------
        buf
            The byte buffer to unpack.
        offset
            The offset in the byte buffer at which to start unpacking this label
            sequence.
        other_offsets
            A set to track offsets that have already been checked, in order to prevent
            loops.

        Returns
        -------
        label
            The label sequence.
        offset
            The offset of the next byte after this label sequence.
        """
        # TODO: Check buffer size.
        if other_offsets is None:
            other_offsets = {offset}
        name: list[bytes] = []
        while (size := buf[offset]) != 0:
            if flags := size & 0b11000000:
                if flags != 0b11000000:
                    raise ValueError(f'Label pointer uses unknown flags {flags}')
                # This is a pointer to another location; mask out the top flag bits.
                pointer = int.from_bytes(buf[offset:offset + 2]) & 0b00111111_11111111
                if pointer in other_offsets:
                    raise ValueError('Label sequence contains a loop')
                if pointer > len(buf):
                    raise ValueError(
                        f'Label pointer ({pointer}) exceeds buffer size ({len(buf)})')
                other_offsets.add(pointer)
                name.extend(LabelSequence.unpack(buf, pointer)[0])
                # Two bytes used for pointer, but we add one below for the last size
                # byte, so only add one here.
                offset += 1
                break
            # Add 1 everywhere to skip the size byte.
            label = buf[offset + 1:offset + size + 1]
            offset += size + 1
            name.append(label)
        return cls(name), offset + 1

    def pack(self) -> bytes:
        """Pack a label sequence into a bytes object."""
        result = []
        for name in self:
            result += [len(name), *name]
        result += [0x00]
        return bytes(result)


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


@dataclasses.dataclass(frozen=True)
class Question:
    """A DNS question."""

    name: LabelSequence
    qtype: QuestionType = bit_field(16)
    qclass: QuestionClass = bit_field(16)

    def __post_init__(self):
        """Validate fields fit within question."""
        _check_bit_fields(self)

    @classmethod
    def unpack(cls, buf: bytes, offset: int) -> tuple[Question, int]:
        """
        Unpack a question out of a byte buffer.

        Parameters
        ----------
        buf
            The byte buffer to unpack.
        offset
            The offset in the byte buffer at which to start unpacking this question.

        Returns
        -------
        question
            The question.
        offset
            The offset of the next byte after this question.
        """
        # TODO: Check buffer size.
        name, offset = LabelSequence.unpack(buf, offset)
        qtype = QuestionType(int.from_bytes(buf[offset:offset + 2]))
        qclass = QuestionClass(int.from_bytes(buf[offset + 2:offset + 4]))
        return cls(name=name, qtype=qtype, qclass=qclass), offset + 4

    def pack(self) -> bytes:
        """Pack a question into a bytes object."""
        result = self.name.pack() + self.qtype.to_bytes(2) + self.qclass.to_bytes(2)
        return result


class AnswerType(enum.IntEnum):
    """
    TYPE fields are used in resource records.

    Note that these types are a subset of QTYPEs.
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


class AnswerClass(enum.IntEnum):
    """CLASS fields appear in resource records."""

    IN = 1  # The Internet.
    CS = 2  # The CSNET class (Obsolete - used only for examples in some obsolete RFCs).
    CH = 3  # The CHAOS class.
    HS = 4  # Hesiod [Dyer 87].


@dataclasses.dataclass
class ResourceRecord:
    """A DNS resource record."""

    name: LabelSequence
    atype: AnswerType = bit_field(16)
    aclass: AnswerClass = bit_field(16)
    ttl: int = bit_field(32)
    data: bytes = b''

    def __post_init__(self):
        """Validate fields fit within resource record."""
        _check_bit_fields(self)

    @classmethod
    def unpack(cls, buf: bytes, offset: int) -> tuple[ResourceRecord, int]:
        """
        Unpack a DNS resource record out of a byte buffer.

        Parameters
        ----------
        buf
            The byte buffer to unpack.
        offset
            The offset in the byte buffer at which to start unpacking this resource
            record.

        Returns
        -------
        record
            The resource record.
        offset
            The offset of the next byte after this resource record.
        """
        name, offset = LabelSequence.unpack(buf, offset)
        atype = AnswerType(int.from_bytes(buf[offset:offset + 2]))
        aclass = AnswerClass(int.from_bytes(buf[offset + 2:offset + 4]))
        ttl = int.from_bytes(buf[offset + 4:offset + 8], signed=True)
        rdlen = int.from_bytes(buf[offset + 8:offset + 10])
        data = buf[offset + 10:offset + rdlen + 10]
        return (cls(name=name, atype=atype, aclass=aclass, ttl=ttl, data=data),
                offset + rdlen + 10)

    def pack(self) -> bytes:
        """Pack a DNS resource record into a bytes object."""
        result = (
            self.name.pack() +
            self.atype.to_bytes(2) + self.aclass.to_bytes(2) +
            self.ttl.to_bytes(4, signed=True) +
            len(self.data).to_bytes(2) + self.data
        )
        return result


@dataclasses.dataclass
class Packet:
    """A DNS packet."""

    header: Header
    questions: tuple[Question, ...] = ()
    answers: tuple[ResourceRecord, ...] = ()

    auto_set_header: dataclasses.InitVar[bool] = False

    def __post_init__(self, auto_set_header: bool) -> None:
        """Refresh header fields if requested."""
        if auto_set_header:
            self.header = dataclasses.replace(
                self.header,
                question_count=len(self.questions),
                answer_record_count=len(self.answers),
                # Not implemented.
                authority_record_count=0,
                additional_record_count=0,
            )

    @classmethod
    def unpack(cls, buf: bytes, offset: int = 0) -> tuple[Packet, int]:
        """
        Unpack a DNS packet out of a byte buffer.

        Parameters
        ----------
        buf
            The byte buffer to unpack.
        offset
            The offset in the byte buffer at which to start unpacking this packet.

        Returns
        -------
        packet
            The DNS packet.
        offset
            The offset of the next byte after this packet.
        """
        header, offset = Header.unpack(buf, offset)

        questions = []
        for i in range(header.question_count):
            question, offset = Question.unpack(buf, offset)
            questions.append(question)

        return cls(header=header, questions=tuple(questions)), offset

    def pack(self) -> bytes:
        """Pack a DNS packet into a bytes object."""
        result = self.header.pack()
        for question in self.questions:
            result += question.pack()
        for record in self.answers:
            result += record.pack()
        return result

    def print(self, indent_level=0, tab_size=4):
        """Print out a DNS packet at a given *indent_level* and *tab_size*."""
        tab = ' ' * tab_size
        initial = tab * indent_level
        print(f'{initial}{self.header}')

        for i, question in enumerate(self.questions):
            print(f'{initial}{tab}Question {i}: {question}')

        for i, record in enumerate(self.answers):
            print(f'{initial}{tab}Answer {i}: {record}')
