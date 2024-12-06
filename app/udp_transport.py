import socket
import threading
from dnslib import DNSRecord

class UDPTransport:
    """
    Handles UDP communication for DNS queries.
    """
    def __init__(self, port, queue):
        self.port = port
        self.queue = queue
        self.server = None

    def listen(self):
        """
        Starts listening for UDP queries.
        """
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("", self.port))
        print(f"UDP transport listening on port {self.port}")

        # Start a thread to handle incoming requests
        threading.Thread(target=self._handle_queries, daemon=True).start()

    def _handle_queries(self):
        """
        Handles incoming DNS queries from the UDP socket.
        """
        while True:
            try:
                # Buffer size for UDP packet
                data, client_addr = self.server.recvfrom(512)  # 512 bytes is max for DNS over UDP
                threading.Thread(target=self._handle_udp_query, args=(data, client_addr), daemon=True).start()
            except Exception as e:
                print(f"Error reading from UDP socket: {e}")

    def _handle_udp_query(self, query_data, client_addr):
        print("handling the udp query now")
        """
        Processes a single DNS query and forwards it to the queue.
        """
        try:
            # Parse the DNS query
            request = DNSRecord.parse(query_data)
            print("I havae parsed the query")
            domain_name = str(request.q.qname)  # Extract domain name from the query
            print("I havae extracted the domain name from the query")
            print(f"Received DNS query for domain: {domain_name} from {client_addr}")

            # Enqueue the query with response handling logic
            self.queue.put({
                "domain_name": domain_name,  # Pass the domain name to the resolver
                "message": request,
                "respond": lambda response: self.server.sendto(response.pack(), client_addr)
            })

        except Exception as e:
            print(f"Error unpacking DNS query from {client_addr}: {e}")

    def close(self):
        """
        Closes the UDP socket.
        """
        if self.server:
            self.server.close()
            print("UDP transport closed")
