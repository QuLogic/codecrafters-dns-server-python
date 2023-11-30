import socket

from . import dns


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            request, bytes_used = dns.Packet.unpack(buf)
            print(f'Received request of {len(buf)} bytes and parsed {bytes_used} bytes')
            print('REQUEST')
            print('=======')
            request.print(indent_level=1)
            print()

            response_code = 0 if request.header.operation_code == 0 else 4
            answers = tuple(
                dns.ResourceRecord(
                    question.name,
                    dns.AnswerType.A,
                    dns.AnswerClass.IN,
                    123 + 10 * i,
                    b'\x01\x02\x03\x04')
                for i, question in enumerate(request.questions))

            response = dns.Packet(
                # Expected header for the "Write header section" stage.
                header=dns.Header(packet_identifier=request.header.packet_identifier,
                                  query_response=1,
                                  operation_code=request.header.operation_code,
                                  authoritative_answer=0, truncation=0,
                                  recursion_desired=request.header.recursion_desired,
                                  recursion_available=0, response_code=response_code),
                questions=request.questions,
                answers=answers,
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
