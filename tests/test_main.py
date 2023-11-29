"""Test for the DNS server."""

import re

import pytest

from app import dns


def test_dns_header_size():
    assert dns.Header.total_bytes == 12


def test_dns_header_invalid():
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


def test_dns_header_unpacking():
    # Expected header for the "Write header section" stage.
    header = dns.Header.unpack(b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00')
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

    # Something non-zero in most fields (except reserved).
    header = dns.Header.unpack(b'\x00\x04\xc2\x8f\x00\x10\x00\x17\x00\x2a\x00\x6c')
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
    assert header.additional_record_count == 108


def test_question_packing():
    question = dns.Question([b'google', b'com'], 1, 1)
    assert question.pack() == b'\x06google\x03com\x00\x00\x01\x00\x01'

    question = dns.Question([b'codecrafters', b'io'], 1, 1)
    assert question.pack() == b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'


def test_question_unpacking():
    question, remaining = dns.Question.unpack(b'\x06google\x03com\x00\x00\x01\x00\x01')
    assert question.name == [b'google', b'com']
    assert question.qtype == 1
    assert question.qclass == 1
    assert remaining == b''

    question, remaining = dns.Question.unpack(
        b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01')
    assert question.name == [b'codecrafters', b'io']
    assert question.qtype == 1
    assert question.qclass == 1
    assert remaining == b''
