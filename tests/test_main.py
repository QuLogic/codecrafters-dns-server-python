"""Test for the DNS server."""

import re

import pytest

from app.main import DNSHeader


def test_dns_header_invalid():
    # Negative value.
    with pytest.raises(ValueError,
                       match=re.escape('packet_identifier (-1) is out of '
                                       'bounds [0, 65535]')):
        DNSHeader(packet_identifier=-1, query_response=0, operation_code=0,
                  authoritative_answer=0, truncation=0, recursion_desired=0,
                  recursion_available=0, response_code=0, question_count=0,
                  answer_record_count=0, authority_record_count=0,
                  additional_record_count=0)

    # A round number of bits.
    with pytest.raises(ValueError,
                       match=re.escape('packet_identifier (131072) is out of '
                                       'bounds [0, 65535]')):
        DNSHeader(packet_identifier=2**17, query_response=0, operation_code=0,
                  authoritative_answer=0, truncation=0, recursion_desired=0,
                  recursion_available=0, response_code=0, question_count=0,
                  answer_record_count=0, authority_record_count=0,
                  additional_record_count=0)

    # A non-byte-aligned number of bits.
    with pytest.raises(ValueError,
                       match=re.escape('operation_code (32) is out of bounds [0, 15]')):
        DNSHeader(packet_identifier=1234, query_response=0, operation_code=2**5,
                  authoritative_answer=0, truncation=0, recursion_desired=0,
                  recursion_available=0, response_code=0, question_count=0,
                  answer_record_count=0, authority_record_count=0,
                  additional_record_count=0)


def test_dns_header_packing():
    header = DNSHeader(packet_identifier=1234, query_response=1, operation_code=0,
                       authoritative_answer=0, truncation=0, recursion_desired=0,
                       recursion_available=0, response_code=0, question_count=0,
                       answer_record_count=0, authority_record_count=0,
                       additional_record_count=0)
