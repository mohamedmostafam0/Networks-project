import threading
import logging
from resolver import resolve_query
from name_cache import NameCache
from resolver_cache import ResolverCache
from authoritative import AuthoritativeServer
from root import RootServer
from tld import TLDServer
from udp_transport import UDPTransport
from tcp_transport import TCPTransport
from queue import Queue
from utils import build_dns_query, parse_dns_query, build_error_response
import tkinter as tk
from tkinter import messagebox


# Setup logging
logging.basicConfig(level=logging.DEBUG)
# DNS server configuration
DNS_SERVER_IP = "0.0.0.0"  # Allow access from any device on the local network
DNS_SERVER_UDP_PORT = 1053
DNS_SERVER_TCP_PORT = 1053

# Constants for DNS message components
QTYPE_A = 1       # A host address (IPv4 addresses)
QTYPE_NS = 2      # An authoritative name server
QTYPE_CNAME = 5   # The canonical name for an alias
QTYPE_SOA = 6     # Marks the start of a zone of authority
QTYPE_PTR = 12    # A domain name pointer (reverse DNS)
QTYPE_MX = 15     # Mail exchange
QTYPE_TXT = 16    # Text strings (TXT records)
QTYPE_AXFR = 252  # Request for transfer of a zone
QTYPE_WKS = 11    # A well-known service description
QTYPE_HINFO = 13  # Host information
QTYPE_MINFO = 14  # Mailbox or mail list information

QCLASS_IN = 1     # Internet (IN) class


def process_queries(queue, authoritative_cache, resolver_cache, root_server, tld_server, authoritative_server):
    while True:
        query_data = queue.get()
        if query_data:
            query_raw = query_data.get('raw_query')
            if query_raw:
                try:
                    transaction_id, domain_name, qtype, qclass = parse_dns_query(query_raw)
                    
                    # Handle IPv6 queries
                    if qtype == 28:
                        logging.info(f"IPv6 query received for {domain_name}, sending Not Implemented")
                        response = build_error_response(query_raw, rcode=4)
                        query_data['respond'](response)
                        continue
                        
                    # Normal processing for other queries
                    response = resolve_query(
                        query_raw,
                        authoritative_cache,
                        resolver_cache,
                        root_server,
                        tld_server,
                        authoritative_server,
                        recursive=True,
                        is_tcp=False
                    )
                    if response:
                        query_data['respond'](response)
                        
                except Exception as e:
                    logging.error(f"Error processing query: {e}")

def start_dns_server():
    """
    Starts the DNS server that listens for queries over UDP and TCP.
    """
    # Initialize components
    authoritative_cache = NameCache(redis_host="localhost", redis_port=6380)  # Authoritative server cache
    resolver_cache = ResolverCache(redis_host="localhost", redis_port=6379)  # Resolver cache
    if(authoritative_cache is None or resolver_cache is None):
        logging.error("Failed to initialize caches")
    authoritative_server = AuthoritativeServer(authoritative_cache)  # Handle authoritative queries    root_server = RootServer()  # Initialize RootServer
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

    udp_thread = threading.Thread(target=process_queries, args=(query_queue, authoritative_cache, resolver_cache, root_server, tld_server, authoritative_server))
    udp_thread.start()

    return authoritative_cache, resolver_cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread

def resolve_domain_gui(domain, cache, root_server, tld_server, authoritative_server):
    """Resolve a domain name from the GUI."""
    try:
        if not domain:
            raise ValueError("No domain name provided")
        query_data = build_dns_query(domain)
        print("your dns query is ", query_data)
        response = resolve_query(query_data, cache, root_server, tld_server, authoritative_server)
        return response
    except Exception as e:
        return f"Error: {str(e)}"

def start_gui(cache, authoritative_server, tld_server, root_server):
    """Start the GUI interface for the DNS resolver."""
    def on_resolve_click():
        domain = domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name.")
            return
        # Resolve domain and update message box with the result
        response = resolve_domain_gui(domain, cache, root_server, tld_server, authoritative_server)
        result_text_box.delete(1.0, tk.END)  # Clear the result text box
        result_text_box.insert(tk.END, response)  # Insert the response in the message box

        # Clear the domain entry after resolution
        domain_entry.delete(0, tk.END)

    def switch_to_terminal():
        choice = input("Enter '1' for terminal interface or '2' for GUI: ").strip()
        if choice == '1':
            start_terminal_interface(cache, authoritative_server, tld_server, root_server)

    # Create the main window with a larger size and improved layout
    root = tk.Tk()
    root.title("DNS Resolver GUI")
    root.geometry("500x350")  # Adjust the window size for better appearance

    # Input field (with a bit more space)
    tk.Label(root, text="Enter Domain Name:", font=("Arial", 12)).grid(row=0, column=0, padx=15, pady=15, sticky="w")
    domain_entry = tk.Entry(root, width=30, font=("Arial", 12))
    domain_entry.grid(row=0, column=1, padx=15, pady=15)

    # Resolve button (styled a bit better)
    resolve_button = tk.Button(root, text="Resolve", command=on_resolve_click, font=("Arial", 12), bg="#007BFF", fg="white", relief="raised", height=2, width=15)
    resolve_button.grid(row=1, column=0, columnspan=2, pady=10)

    # Output text box (reduced size and more readable)
    result_text_box = tk.Text(root, height=6, width=40, font=("Arial", 12), wrap="word", relief="solid") 
    result_text_box.grid(row=2, column=0, columnspan=2, padx=15, pady=15)

    # Add a button to switch to the terminal interface
    switch_button = tk.Button(root, text="Switch to Terminal", command=switch_to_terminal, font=("Arial", 12), bg="#007BFF", fg="white", relief="raised", height=2, width=15)
    switch_button.grid(row=3, column=0, columnspan=2, pady=15)

    # Run the Tkinter loop
    root.mainloop()


def start_terminal_interface(cache, authoritative_server, tld_server, root_server):
    """Start the terminal interface for DNS resolution."""
    logging.info("Starting terminal-based DNS resolution...")
    while True:
        domain_to_resolve = input("Enter the domain you want to resolve (or press Ctrl+C to exit): ").strip()
        
        if domain_to_resolve:
            # Ask if the user wants a recursive or iterative query
            query_approach = input("Do you want a recursive (r) or iterative (i) query? (r/i): ").strip().lower()
            qtype = input("Enter query type: ").strip().upper()
            qtype_map = {
            "A": QTYPE_A,
            "NS": QTYPE_NS,
            "CNAME": QTYPE_CNAME,
            "SOA": QTYPE_SOA,
            "PTR": QTYPE_PTR,
            "MX": QTYPE_MX,
            "TXT": QTYPE_TXT,
            "AXFR": QTYPE_AXFR,
            "WKS": QTYPE_WKS,
            "HINFO": QTYPE_HINFO,
            "MINFO": QTYPE_MINFO
            }
            qtype = qtype_map.get(qtype)
            if not qtype:
                print("invalid query type")
            if query_approach == 'r':
                logging.info(f"Domain to resolve (recursive): {domain_to_resolve}")
                # For recursive query, pass the appropriate flag to resolve_query
                query_data = build_dns_query(domain_to_resolve, qtype)
                logging.info(f"Your DNS message is {query_data}")
                response = resolve_query(query_data, cache, root_server, tld_server, authoritative_server, recursive=True, is_tcp=False)
                logging.info(f"Resolved response: {response}")
            elif query_approach == 'i':
                logging.info(f"Domain to resolve (iterative): {domain_to_resolve}")
                # For iterative query, pass the appropriate flag to resolve_query
                query_data = build_dns_query(domain_to_resolve, qtype)
                logging.info(f"Your DNS message is {query_data}")
                response = resolve_query(query_data, cache, root_server, tld_server, authoritative_server, recursive=False, is_tcp=False)
                logging.info(f"Resolved response: {response}")
            else:
                print("Invalid input. Please enter 'r' for recursive or 'i' for iterative.")
        else:
            print("No domain entered. Please try again.")

def main():
    logging.info("Starting the DNS Server Agent...")

    authoritative_cache, resolver_cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread = start_dns_server()
    
    if authoritative_server is None:
        logging.error("Failed to start DNS server.")
    else:
        try:
            # Choose interface
            choice = input("Enter '1' for terminal interface or '2' for GUI: ").strip()
            if choice == '1':
                print("ok")
                # start_terminal_interface(cache, authoritative_server, tld_server, root_server)
            elif choice == '2':
                print("ok")
                # start_gui(cache, authoritative_server, tld_server, root_server)
            else:
                print("Invalid choice. Exiting.")
        
        except KeyboardInterrupt:
            print("\nShutting down the DNS Server. Goodbye!")
            logging.info("Shutting down DNS server...")
            
            # Save master files on shutdown
            authoritative_server.save_master_files()            
            
            # Close resources
            udp_transport.close()
            tcp_transport.close()
            udp_thread.join()

if __name__ == "__main__":
    main()
