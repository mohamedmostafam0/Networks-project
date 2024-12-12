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
import tkinter as tk
from tkinter import messagebox
# Setup logging
logging.basicConfig(level=logging.DEBUG)
# DNS server configuration
DNS_SERVER_IP = "localhost"
DNS_SERVER_UDP_PORT = 1054
DNS_SERVER_TCP_PORT = 1054
def process_queries(queue, cache, root_server, tld_server, authoritative_server):
    """
    Processes DNS queries received from the transport layer.
    """
    print("Processing your query")
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

    udp_thread = threading.Thread(target=process_queries, args=(query_queue, cache, root_server, tld_server, authoritative_server))
    udp_thread.start()

    return cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread

def resolve_domain_gui(domain, cache, root_server, tld_server, authoritative_server):
    """Resolve a domain name from the GUI."""
    try:
        if not domain:
            raise ValueError("No domain name provided")
        query_data = build_dns_query(domain)
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
            logging.info(f"Domain to resolve: {domain_to_resolve}")
            query_data = build_dns_query(domain_to_resolve)
            response = resolve_query(query_data, cache, root_server, tld_server, authoritative_server)
            logging.info(f"Resolved response: {response}")
        else:
            print("No domain entered. Please try again.")

def main():
    logging.info("Starting the DNS Server Agent...")

    cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread = start_dns_server()
    
    if cache is None or authoritative_server is None:
        logging.error("Failed to start DNS server.")
    else:
        try:
            # Choose interface
            choice = input("Enter '1' for terminal interface or '2' for GUI: ").strip()
            if choice == '1':
                start_terminal_interface(cache, authoritative_server, tld_server, root_server)
            elif choice == '2':
                start_gui(cache, authoritative_server, tld_server, root_server)
            else:
                print("Invalid choice. Exiting.")
        except KeyboardInterrupt:
            print("\nShutting down the DNS Server. Goodbye!")
            logging.info("Shutting down DNS server...")
            # Close resources
            udp_transport.close()
            tcp_transport.close()
            udp_thread.join()

if __name__ == "__main__":
    main()
