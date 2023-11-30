"""Test for the DNS server."""

import re

import pytest

from app import dns


def test_dns_header_size():
    assert dns.Header.total_bytes == 12


def test_dns_header_invalid():
    # Too small.
    with pytest.raises(ValueError,
                       match='Buffer of length 1 is smaller than expected.*'):
        dns.Header.unpack(b'\x00', 0)
    with pytest.raises(ValueError,
                       match='Buffer of length 2 is smaller than expected.*'):
        dns.Header.unpack(b'\x00' * 12, 10)

    # Negative value.
    with pytest.raises(ValueError,
                       match=re.escape('packet_identifier (-1) is out of '
                                       'bounds [0, 65535]')):
        dns.Header(packet_identifier=-1, query_response=0, operation_code=0,
                   authoritative_answer=0, truncation=0, recursion_desired=0,
                   recursion_available=0, response_code=0, question_count=0,
                   answer_record_count=0, authority_record_count=0,
                   additional_record_count=0)

    # A round number of bits.
    with pytest.raises(ValueError,
                       match=re.escape('packet_identifier (131072) is out of '
                                       'bounds [0, 65535]')):
        dns.Header(packet_identifier=2**17, query_response=0, operation_code=0,
                   authoritative_answer=0, truncation=0, recursion_desired=0,
                   recursion_available=0, response_code=0, question_count=0,
                   answer_record_count=0, authority_record_count=0,
                   additional_record_count=0)

    # A non-byte-aligned number of bits.
    with pytest.raises(ValueError,
                       match=re.escape('operation_code (32) is out of bounds [0, 15]')):
        dns.Header(packet_identifier=1234, query_response=0, operation_code=2**5,
                   authoritative_answer=0, truncation=0, recursion_desired=0,
                   recursion_available=0, response_code=0, question_count=0,
                   answer_record_count=0, authority_record_count=0,
                   additional_record_count=0)


def test_dns_header_packing():
    # Expected header for the "Write header section" stage.
    header = dns.Header(packet_identifier=1234, query_response=1, operation_code=0,
                        authoritative_answer=0, truncation=0, recursion_desired=0,
                        recursion_available=0, response_code=0, question_count=0,
                        answer_record_count=0, authority_record_count=0,
                        additional_record_count=0)
    assert header.pack() == b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # Add something non-zero in most fields (except reserved).
    header = dns.Header(packet_identifier=4, query_response=1, operation_code=8,
                        authoritative_answer=0, truncation=1, recursion_desired=0,
                        recursion_available=1, response_code=15, question_count=16,
                        answer_record_count=23, authority_record_count=42,
                        additional_record_count=108)
    assert header.pack() == b'\x00\x04\xc2\x8f\x00\x10\x00\x17\x00\x2a\x00\x6c'


@pytest.mark.parametrize('start_offset', [0, 10])
def test_dns_header_unpacking(start_offset):
    # Expected header for the "Write header section" stage.
    header, offset = dns.Header.unpack(
        b'\x42' * start_offset + b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        start_offset)
    assert header.packet_identifier == 1234
    assert header.query_response == 1
    assert header.operation_code == 0
    assert header.authoritative_answer == 0
    assert header.truncation == 0
    assert header.recursion_desired == 0
    assert header.recursion_available == 0
    assert header.response_code == 0
    assert header.question_count == 0
    assert header.answer_record_count == 0
    assert header.authority_record_count == 0
    assert header.additional_record_count == 0
    assert offset == start_offset + 12

    # Something non-zero in most fields (except reserved).
    header, offset = dns.Header.unpack(
        b'\x42' * start_offset + b'\x00\x04\xc2\x8f\x00\x10\x00\x17\x00\x2a\x00\x6c',
        start_offset)
    assert header.packet_identifier == 4
    assert header.query_response == 1
    assert header.operation_code == 8
    assert header.authoritative_answer == 0
    assert header.truncation == 1
    assert header.recursion_desired == 0
    assert header.recursion_available == 1
    assert header.response_code == 15
    assert header.question_count == 16
    assert header.answer_record_count == 23
    assert header.authority_record_count == 42
    assert offset == start_offset + 12


def test_label_sequence_invalid():
    with pytest.raises(ValueError, match=r'.*longer than 63.*'):
        dns.LabelSequence([b'A' * 200])
    with pytest.raises(ValueError, match=r'.*does not obey DNS rules'):
        dns.LabelSequence([b'0'])
    with pytest.raises(ValueError, match=r'.*does not obey DNS rules'):
        dns.LabelSequence([b'0foo'])
    with pytest.raises(ValueError, match=r'.*does not obey DNS rules'):
        dns.LabelSequence([b'foo0-'])
    with pytest.raises(ValueError, match=r'.*does not obey DNS rules'):
        dns.LabelSequence([b'f!o0'])


def test_label_sequence_packing():
    name = dns.LabelSequence([b'google', b'com'])
    assert name.pack() == b'\x06google\x03com\x00'

    name = dns.LabelSequence([b'codecrafters', b'io'])
    assert name.pack() == b'\x0ccodecrafters\x02io\x00'


@pytest.mark.parametrize('start_offset', [0, 10])
def test_label_sequence_unpacking(start_offset):
    buf = b'\x0ccodecrafters\x02io\x00'
    name, offset = dns.LabelSequence.unpack(b'\x42' * start_offset + buf, start_offset)
    assert name == (b'codecrafters', b'io')
    assert offset == start_offset + len(buf)


def test_label_sequence_invalid_compression():
    with pytest.raises(ValueError, match='Label pointer uses unknown flags.*'):
        dns.LabelSequence.unpack(b'\x80\x00', 0)
    with pytest.raises(ValueError, match='Label pointer uses unknown flags.*'):
        dns.LabelSequence.unpack(b'\x40\x00', 0)
    with pytest.raises(ValueError, match='Label sequence contains a loop'):
        dns.LabelSequence.unpack(b'\xc0\x00', 0)
    with pytest.raises(ValueError,
                       match=r'Label pointer \(66\) exceeds buffer size \(2\)'):
        dns.LabelSequence.unpack(b'\xc0\x42', 0)


def test_label_sequence_compression():
    # Example from the RFC.
    buf = b'\x42' * 20 + b'\x01F\x03ISI\x04ARPA\x00\03FOO\xc0\x14\xc0\x1a\x00'
    names = []
    offset = 20
    while offset < len(buf):
        name, offset = dns.LabelSequence.unpack(buf, offset)
        names.append(name)
    assert names == [
        (b'F', b'ISI', b'ARPA'),
        (b'FOO', b'F', b'ISI', b'ARPA'),
        (b'ARPA', ),
        (),
    ]


def test_question_packing():
    question = dns.Question(dns.LabelSequence([b'google', b'com']),
                            dns.QuestionType.A,
                            dns.QuestionClass.IN)
    assert question.pack() == b'\x06google\x03com\x00\x00\x01\x00\x01'

    question = dns.Question(dns.LabelSequence([b'codecrafters', b'io']),
                            dns.QuestionType.A,
                            dns.QuestionClass.IN)
    assert question.pack() == b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'


@pytest.mark.parametrize('start_offset', [0, 10])
def test_question_unpacking(start_offset):
    buf = b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'
    question, offset = dns.Question.unpack(b'\x42' * start_offset + buf, start_offset)
    assert question.name == (b'codecrafters', b'io')
    assert question.qtype == dns.QuestionType.A
    assert question.qclass == dns.QuestionClass.IN
    assert offset == start_offset + len(buf)


def test_resource_record_packing():
    rr = dns.ResourceRecord(
        dns.LabelSequence([b'codecrafters', b'io']),
        dns.AnswerType.A,
        dns.AnswerClass.IN,
        60,
        b'\x08\x08\x08\x08')
    assert rr.pack() == (
        b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
        b'\x08\x08\x08\x08')


@pytest.mark.parametrize('start_offset', [0, 10])
def test_resource_record_unpacking(start_offset):
    buf = (
        b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
        b'\x08\x08\x08\x08')
    rr, offset = dns.ResourceRecord.unpack(b'\x42' * start_offset + buf, start_offset)
    assert rr.name == (b'codecrafters', b'io')
    assert rr.atype == dns.AnswerType.A
    assert rr.aclass == dns.AnswerClass.IN
    assert rr.ttl == 60
    assert rr.data == b'\x08\x08\x08\x08'
    assert offset == start_offset + len(buf)
