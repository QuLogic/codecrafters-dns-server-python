import socket

from .dns import DNSHeader


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Expected header for the "Write header section" stage.
            header = DNSHeader(packet_identifier=1234, query_response=1,
                               operation_code=0, authoritative_answer=0, truncation=0,
                               recursion_desired=0, recursion_available=0,
                               response_code=0, question_count=0, answer_record_count=0,
                               authority_record_count=0, additional_record_count=0)
            response = header.pack()

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
