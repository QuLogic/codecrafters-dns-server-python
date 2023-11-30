import socket
import typing

from . import dns


class OpenRequest:
    """Helper class to track an open request."""

    def __init__(self, source: tuple[str, int], request: dns.Packet):
        self.source = source
        self.request = request
        self.answers: dict[dns.Question, dns.ResourceRecord | None] = {
            question: None for question in request.questions}

    def __hash__(self):
        return hash((self.source, self.request.header.packet_identifier))

    @property
    def is_complete(self) -> bool:
        """Whether this request is complete."""
        return all(value is not None for value in self.answers.values())

    def add_response(self, response: dns.Packet) -> None:
        """Add a response to this open request."""
        for answer in response.answers:
            question = dns.Question(answer.name, dns.QuestionType(answer.atype),
                                    dns.QuestionClass(answer.atype))
            self.answers[question] = answer

    def to_response(self) -> dns.Packet:
        """Convert to a response packet, if this request is complete."""
        if not self.is_complete:
            raise ValueError('Cannot convert open request to response')
        response_code = 0 if self.request.header.operation_code == 0 else 4
        answers = typing.cast(dict[dns.Question, dns.ResourceRecord],  # When complete.
                              self.answers)
        response = dns.Packet(
            header=dns.Header(packet_identifier=self.request.header.packet_identifier,
                              query_response=1,
                              operation_code=self.request.header.operation_code,
                              authoritative_answer=0, truncation=0,
                              recursion_desired=self.request.header.recursion_desired,
                              recursion_available=0, response_code=response_code),
            questions=self.request.questions,
            answers=tuple(answers.values()),
            auto_set_header=True,
        )
        return response


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    open_requests = set()

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            request, bytes_used = dns.Packet.unpack(buf)
            print(f'Received request of {len(buf)} bytes and parsed {bytes_used} bytes')
            print('REQUEST')
            print('=======')
            request.print(indent_level=1)
            print()
            open_request = OpenRequest(source, request)
            open_requests.add(open_request)

            # Add default answers.
            for i, question in enumerate(open_request.request.questions):
                open_request.answers[question] = dns.ResourceRecord(
                    question.name,
                    dns.AnswerType.A,
                    dns.AnswerClass.IN,
                    123 + 10 * i,
                    b'\x01\x02\x03\x04')

            if open_request is not None and open_request.is_complete:
                response = open_request.to_response()
                print('RESPONSE')
                print('========')
                response.print(indent_level=1)
                print()

                udp_socket.sendto(response.pack(), open_request.source)
                open_requests.remove(open_request)
        except Exception as e:
            print(f"Error receiving data: {e}")
            import traceback
            traceback.print_exception(e)
            break


if __name__ == "__main__":
    main()
