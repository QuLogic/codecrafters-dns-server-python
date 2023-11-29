import socket

from . import dns


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            request = dns.Packet.unpack(buf)
            print('REQUEST')
            print('=======')
            request.print(indent_level=1)
            print()

            answer = dns.ResourceRecord(
                dns.LabelSequence([b'codecrafters', b'io']),
                dns.AnswerType.A,
                dns.AnswerClass.IN,
                123,
                b'\x01\x02\x03\x04')

            response = dns.Packet(
                # Expected header for the "Write header section" stage.
                header=dns.Header(packet_identifier=1234, query_response=1,
                                  operation_code=0, authoritative_answer=0,
                                  truncation=0, recursion_desired=0,
                                  recursion_available=0, response_code=0),
                questions=request.questions,
                answers=(answer, ),
                auto_set_header=True,
            )
            print('RESPONSE')
            print('========')
            response.print(indent_level=1)
            print()

            udp_socket.sendto(response.pack(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            import traceback
            traceback.print_exception(e)
            break


if __name__ == "__main__":
    main()
