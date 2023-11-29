import dataclasses
import socket


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            response = b""

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


def bit_field(width):
    """Create a bit field with given *width*."""
    return dataclasses.field(metadata={'width': width})


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
    reserved: int = bit_field(3)
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


if __name__ == "__main__":
    main()
