import struct
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
    format_ns_name,
)

# Set up logging
logging.basicConfig(level=logging.DEBUG)


class TLDServer:
    def __init__(self):
        """
        Initializes the TLD server with a mapping of second-level domains to
        authoritative server addresses.
        """
        self.authoritative_mapping = {
            "example.com": "192.168.2.10",
            "mywebsite.com": "192.168.2.11",
            "opensource.org": "192.168.2.12",
            "networking.net": "192.168.2.13",
            "university.edu": "192.168.2.14",
            "government.gov": "192.168.2.15",
            "techstartup.io": "192.168.2.16",
            "innovators.tech": "192.168.2.17",
        }
        self.ttl = 3600  # Default TTL for records

    def handle_query(self, query):
        """
        Handles DNS queries by referring them to the correct authoritative server.
        """
        try:
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
            domain_name = domain_name.lower()  # Ensure case-insensitivity
            print("your query is for: " + domain_name)
        except ValueError as e:
            logging.error(f"Invalid query: {e}")
            print("building error response")
            return self.build_error_response(query, rcode=1)  # Format error (RCODE 1)
        # Find the authoritative server for the domain
        authoritative_server_address = self.find_authoritative_server(domain_name)
        if authoritative_server_address:
            logging.info(
                f"Referring query for {domain_name} to authoritative server at {authoritative_server_address}"
            )
            return self.build_referral_response(query, domain_name, authoritative_server_address)

        # If no match found, return NXDOMAIN
        logging.error(f"Domain {domain_name} not found in TLD server mapping.")
        return self.build_error_response(query, rcode=3)  # NXDOMAIN

    def find_authoritative_server(self, domain_name):
        """
        Finds the authoritative server for the given domain name.
        Supports hierarchical domain matching.
        """
        parts = domain_name.split(".")
        for i in range(len(parts)):
            domain_to_check = ".".join(parts[i:])
            if domain_to_check in self.authoritative_mapping:
                return self.authoritative_mapping[domain_to_check]
        return None

    def build_referral_response(self, query, domain_name, next_server_ip):
        """
        Constructs a referral response pointing to the next server.
        """
        transaction_id, _, qtype, qclass = parse_dns_query(query)

        # DNS header
        flags = 0x8180  # Standard query response, authoritative answer
        qd_count = 1  # One question
        an_count = 0  # No answer records
        ns_count = 1  # One authority record
        ar_count = 1  # One additional record
        header = build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)

        # Question Section
        question = build_dns_question(domain_name, qtype, qclass)

        # Authority Section (NS record)
        authority_rr = build_rr(
            name=domain_name,
            rtype=2,  # NS record
            rclass=1,  # IN class
            ttl=self.ttl,  # Time-to-live
            rdata=format_ns_name("ns1.authoritative-server.com"),
        )

        # Additional Section (A record for next server)
        additional_rr = build_rr(
            name="ns1.authoritative-server.com",
            rtype=1,  # A record
            rclass=1,  # IN class
            ttl=self.ttl,  # Time-to-live
            rdata=ip_to_bytes(next_server_ip),
        )

        return header + question + authority_rr + additional_rr

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
