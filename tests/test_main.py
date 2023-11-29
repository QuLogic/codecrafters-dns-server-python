"""Test for the DNS server."""

from app.main import DNSHeader


def test_dns_header():
    header = DNSHeader(packet_identifier=1234, query_response=1, operation_code=0,
                       authoritative_answer=0, truncation=0, recursion_desired=0,
                       recursion_available=0, response_code=0, question_count=0,
                       answer_record_count=0, authority_record_count=0,
                       additional_record_count=0)
