import socket
import threading
import logging
from resolver import resolve_query
from cache import Cache
from authoritative import AuthoritativeServer
from root import RootServer
from tld import TLDServer
from udp_transport import UDPTransport
from tcp_transport import TCPTransport
from queue import Queue
from utils import build_dns_query
import random
import time

# Setup logging
logging.basicConfig(level=logging.DEBUG)

# DNS server configuration
DNS_SERVER_IP = "localhost"
DNS_SERVER_UDP_PORT = 1053
DNS_SERVER_TCP_PORT = 1053

def process_queries(queue, cache, root_server, tld_server, authoritative_server):
    """
    Processes DNS queries received from the transport layer.
    """
    print("processing your query")
    while True:
        query_data = queue.get()
        if query_data:
            domain_name = query_data['domain_name']
            request = query_data['message']
            respond = query_data['respond']
            logging.info(f"Resolving query for domain: {domain_name}")

            # Process and resolve query
            response = resolve_query(request, cache, root_server, tld_server, authoritative_server)

            # Send the response back to the client
            respond(response)

def handle_udp_queries(queue, cache, root_server, tld_server, authoritative_server):
    """
    Handle incoming DNS queries over UDP.
    """
    logging.info("Listening for UDP queries...")
    process_queries(queue, cache, root_server, tld_server, authoritative_server)

def handle_tcp_queries(queue, cache, root_server, tld_server, authoritative_server):
    """
    Handle incoming DNS queries over TCP.
    """
    logging.info("Listening for TCP queries...")
    process_queries(queue, cache, root_server, tld_server, authoritative_server)

def start_dns_server():
    """
    Starts the DNS server that listens for queries over UDP and TCP.
    """
    # Initialize components
    cache = Cache()  # Initialize Redis-based cache
    authoritative_server = AuthoritativeServer(cache)  # Handle authoritative queries
    root_server = RootServer()  # Initialize RootServer
    tld_server = TLDServer()    # Initialize TLDServer
    
    query_queue = Queue()

    # Start UDP transport
    udp_transport = UDPTransport(DNS_SERVER_UDP_PORT, query_queue)
    udp_transport.listen()

    # Start TCP transport
    tcp_transport = TCPTransport(DNS_SERVER_TCP_PORT, query_queue)
    tcp_transport.listen()

    logging.info(f"DNS server is running on {DNS_SERVER_IP}:{DNS_SERVER_UDP_PORT} for UDP...")
    logging.info(f"DNS server is running on {DNS_SERVER_IP}:{DNS_SERVER_TCP_PORT} for TCP...")

    udp_thread = threading.Thread(target=handle_udp_queries, args=(query_queue, cache, root_server, tld_server, authoritative_server))
    tcp_thread = threading.Thread(target=handle_tcp_queries, args=(query_queue, cache, root_server, tld_server, authoritative_server))

    udp_thread.start()
    tcp_thread.start()

    return cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread, tcp_thread

def main():
    logging.info("Starting the DNS Server Agent...")

    cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread, tcp_thread = start_dns_server()
    # print(f"root_server is of type: {type(root_server)}")
    # print(f"root_server is of type: {type(tld_server)}")
    # print(f"root_server is of type: {type(authoritative_server)}")
    
    if cache is None or authoritative_server is None:
        logging.error("Failed to start DNS server.")
    else:
        try:
            while True:
                # Interactive user input for domain resolution
                domain_to_resolve = input("Enter the domain you want to resolve (or press Ctrl+C to exit): ").strip()
                if domain_to_resolve:
                    logging.info(f"Domain to resolve: {domain_to_resolve}")
                    query_data = build_dns_query(domain_to_resolve)
                    print("built the dns question of ", query_data)
                    response = resolve_query(query_data, cache, root_server, tld_server, authoritative_server)
                    logging.info(f"resolved response: {response}")
                else:
                    print("No domain entered. Please try again.")
        except KeyboardInterrupt:
            print("\nShutting down the DNS Server. Goodbye!")
            logging.info("Shutting down DNS server...")
            # Close the transport and stop threads
            udp_transport.close()
            tcp_transport.close()
            udp_thread.join()
            tcp_thread.join()

if __name__ == "__main__":
    main()
