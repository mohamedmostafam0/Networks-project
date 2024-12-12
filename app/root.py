import tldextract
import logging
from utils import (
    build_dns_header,
    build_dns_question,
    build_rr,
    parse_dns_query,
    validate_query,
    build_error_response,
    ip_to_bytes,
    bytes_to_ip,
    format_ns_name
)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class RootServer:
    def __init__(self):
        # Mapping of TLDs to TLD server addresses (expanded dummy data)
        self.tld_mapping = {
            "com": "192.168.1.10",
            "org": "192.168.1.11",
            "net": "192.168.1.12",
            "edu": "192.168.1.13",
            "gov": "192.168.1.14",
            "io": "192.168.1.15",
            "tech": "192.168.1.16",
        }


    def handle_root_query(self, query):
        """
        Handles DNS queries by referring them to the correct TLD server.
        """
        domain_name = self.extract_domain_name(query)
        tld = self.get_tld(domain_name)
        if tld in self.tld_mapping:
            tld_server_address = self.tld_mapping[tld]
            logging.info(f"Referring query for {domain_name} to TLD server at {tld_server_address}")
            return self.build_referral_response(query, domain_name, tld_server_address)
        
        logging.error(f"TLD {tld} not found in root server mapping.")
        return self.build_error_response(query, rcode=3)  # NXDOMAIN

    @staticmethod
    def extract_domain_name(query):
        """
        Extracts the domain name from the DNS query.
        """
        # Extract the domain name part from the query (skipping header).
        query = query[12:]  # Skip the DNS header (first 12 bytes)
        labels = []
        while query:
            length = query[0]
            if length == 0:
                break
            labels.append(query[1:1+length].decode())
            query = query[1+length:]
        return ".".join(labels)

    @staticmethod
    def get_tld(domain_name):
        """
        Extracts the top-level domain (TLD) from a domain name.
        """
        extracted = tldextract.extract(domain_name)
        return extracted.suffix  # Returns the full TLD (e.g., "com", "co.uk")
    
    @staticmethod
    def build_referral_response(query, ns_domain, ns_address):
        """
        Constructs a referral response pointing to a name server.
        
        Parameters:
            query (bytes): The raw DNS query.
            ns_domain (str): The domain name of the name server (e.g., "ns.example.com").
            ns_address (str): The IP address of the name server (e.g., "192.168.1.1").
        
        Returns:
            bytes: The DNS referral response.
        """
        # Parse the query to extract necessary details
        transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
        
        # DNS Header
        flags = 0x8180  # Standard query response (QR=1, AA=0, RCODE=0)
        qd_count = 1  # Number of questions
        an_count = 0  # Number of answers
        ns_count = 1  # Number of authority records
        ar_count = 1  # Number of additional records
        
        # Build the DNS header
        header = build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)
        
        # Question Section
        question = build_dns_question(domain_name, qtype, qclass)
        
        # Authority Section (NS Record)
        ns_record = build_rr(
            name=domain_name,  # The queried domain
            rtype=2,  # NS record
            rclass=1,  # IN class
            ttl=3600,  # TTL in seconds
            rdata=format_ns_name(ns_domain)  # Ensure this returns a string
        )
        
        # Additional Section (A Record for the Name Server)
        additional_record = build_rr(
            name=ns_domain,  # Pass as a string
            rtype=1,  # A record
            rclass=1,  # IN class
            ttl=3600,  # TTL in seconds
            rdata=ip_to_bytes(ns_address)  # Name server IP address as bytes
        )
        
        # Return the constructed DNS response
        return header + question + ns_record + additional_record



    @staticmethod
    def build_error_response(query, rcode):
        """
        Constructs a DNS response with an error (e.g., NXDOMAIN).
        """
        transaction_id, domain_name, qtype, qclass = parse_dns_query(query)

        # DNS Header
        flags = 0x8180 | rcode  # Standard query response with error code
        qd_count = 1  # One question
        an_count = 0  # No answer records
        ns_count = 0  # No authority records
        ar_count = 0  # No additional records
        header = build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)

        # Question Section (copy from query)
        question = build_dns_question(domain_name, qtype, qclass)

        return header + question
    
    
    def build_error_response(self, query, rcode):
        """
        Constructs a DNS response with an error (e.g., NXDOMAIN).
        """
        try:
            transaction_id, _, _, _ = parse_dns_query(query)
        except ValueError as e:
            logging.error(f"Failed to parse query for error response: {e}")
            return b""  # Return an empty response if query parsing fails

        flags = 0x8180 | rcode  # Standard query response with the provided error code
        qd_count = 1  # One question
        an_count = 0  # No answer records
        ns_count = 0  # No authority records
        ar_count = 0  # No additional records
        header = build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)
        question = query[12:]  # Include the original question section
        return header + question
