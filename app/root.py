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
        # Mapping of TLDs to TLD server addresses (expanded with more dummy data)
        self.tld_mapping = {
            "com": "192.168.1.10",
            "org": "192.168.1.11",
            "net": "192.168.1.12",
            "edu": "192.168.1.13",
            "gov": "192.168.1.14",
            "io": "192.168.1.15",
            "tech": "192.168.1.16",
            "co": "192.168.1.17",
            "us": "192.168.1.18",
            "ca": "192.168.1.19",
            "uk": "192.168.1.20",
            "de": "192.168.1.21",
            "fr": "192.168.1.22",
            "jp": "192.168.1.23",
            "in": "192.168.1.24",
            "au": "192.168.1.25",
            "cn": "192.168.1.26",
            "br": "192.168.1.27",
            "mx": "192.168.1.28",
            "ru": "192.168.1.29",
            "za": "192.168.1.30",
            "ch": "192.168.1.31",
            "it": "192.168.1.32",
            "es": "192.168.1.33",
            "se": "192.168.1.34",
            "pl": "192.168.1.35",
            "no": "192.168.1.36",
            "fi": "192.168.1.37",
            "nl": "192.168.1.38",
            "kr": "192.168.1.39",
            "sg": "192.168.1.40",
            "hk": "192.168.1.41",
            "ae": "192.168.1.42",
            "sa": "192.168.1.43",
            "cl": "192.168.1.44",
            "ar": "192.168.1.45",
            "eg": "192.168.1.46",
            "tr": "192.168.1.47",
            "vn": "192.168.1.48",
            "my": "192.168.1.49",
            "kr": "192.168.1.50",
            "id": "192.168.1.51",
            "pk": "192.168.1.52",
            "ng": "192.168.1.53",
            "th": "192.168.1.54",
            "bd": "192.168.1.55",
            "ph": "192.168.1.56",
            "kw": "192.168.1.57",
            "kw": "192.168.1.58",
            "gr": "192.168.1.59",
            "cz": "192.168.1.60",
            "hk": "192.168.1.61",
            "ua": "192.168.1.62",
            "by": "192.168.1.63",
            "hr": "192.168.1.64",
            "si": "192.168.1.65",
            "at": "192.168.1.66",
            "be": "192.168.1.67",
            "lu": "192.168.1.68",
            "li": "192.168.1.69",
            "is": "192.168.1.70",
            "mt": "192.168.1.71",
            "rs": "192.168.1.72",
            "me": "192.168.1.73",
            "mk": "192.168.1.74",
            "gd": "192.168.1.75",
            "lt": "192.168.1.76",
            "ee": "192.168.1.77",
            "lv": "192.168.1.78",
            "ge": "192.168.1.79",
            "am": "192.168.1.80",
            "kg": "192.168.1.81",
            "md": "192.168.1.82",
            "uz": "192.168.1.83",
            "tj": "192.168.1.84",
            "tm": "192.168.1.85",
            "kp": "192.168.1.86",
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
            return self.build_referral_response(query, domain_name, tld, tld_server_address)
        
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
    def build_referral_response(query, ns_domain, tld, ns_address):
        """
        Constructs a referral response pointing to a name server.

        Parameters:
            query (bytes): The raw DNS query.
            ns_domain (str): The domain name of the name server (e.g., "a.gtld-servers.net").
            tld (str): The top-level domain being referred (e.g., "com").
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
            name=tld,  # Referring the TLD (e.g., "com")
            rtype=2,  # NS record
            rclass=1,  # IN class
            ttl=3600,  # TTL in seconds
            rdata=format_ns_name(ns_domain)  # Name of the NS server (e.g., "a.gtld-servers.net.")
        )
        
        # Additional Section (A Record for the Name Server)
        additional_record = build_rr(
            name=ns_domain,  # Name of the NS server (e.g., "a.gtld-servers.net")
            rtype=1,  # A record
            rclass=1,  # IN class
            ttl=3600,  # TTL in seconds
            rdata=ip_to_bytes(ns_address)  # Convert the IP address to bytes (e.g., "192.168.1.1" -> b'\xc0\xa8\x01\x01')
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