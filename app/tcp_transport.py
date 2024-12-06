import socket
import threading
from dnslib import DNSRecord

class TCPTransport:
    def __init__(self, port, queue):
        self.port = port
        self.queue = queue
        self.server = None

    def listen(self):
        """
        Starts listening for TCP queries.
        """
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("", self.port))
        self.server.listen(5)
        threading.Thread(target=self._accept_connections, daemon=True).start()
        print(f"TCP transport listening on port {self.port}")

    def _accept_connections(self):
        while True:
            conn, addr = self.server.accept()
            threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()

    def _handle_connection(self, conn):
        with conn:
            while True:
                try:
                    length = int.from_bytes(conn.recv(2), "big")
                    data = conn.recv(length)
                    request = DNSRecord.parse(data)
                    self.queue.put({
                        "domain_name": str(request.q.qname),  # Pass the domain name to the resolver
                        "message": request,
                        "respond": lambda response: conn.sendall(len(response.pack()).to_bytes(2, "big") + response.pack())
                    })
                except Exception as e:
                    print(f"Error in TCP connection: {e}")
                    break

    def close(self):
        """
        Closes the TCP socket.
        """
        if self.server:
            self.server.close()
            print("TCP transport closed")
