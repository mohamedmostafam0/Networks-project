import struct
import logging
from cache import Cache  # Import the Cache class
from utils import parse_dns_query
# Set up logging
logging.basicConfig(level=logging.DEBUG)

class AuthoritativeServer:
    def __init__(self, cache: Cache):
        """
        Initializes the authoritative DNS server with some predefined DNS records.
        """
        self.cache = cache  # Use the passed-in cache instance
        self.records = {
            "example.com": {
                "A": ["93.184.216.34"],
                "NS": ["ns1.example.com.", "ns2.example.com."],
                "MX": ["10 mail.example.com."],
                "SOA": ["ns1.example.com. admin.example.com. 2023120301 7200 3600 1209600 86400"],
                "PTR": ["example.com."],
            },
            "mywebsite.com": {
                "A": ["93.184.216.35"],
                "NS": ["ns1.mywebsite.com.", "ns2.mywebsite.com."],
                "MX": ["10 mail.mywebsite.com."],
                "SOA": ["ns1.mywebsite.com. admin.mywebsite.com. 2023120302 7200 3600 1209600 86400"],
            },
            "opensource.org": {
                "A": ["93.184.216.36"],
                "NS": ["ns1.opensource.org.", "ns2.opensource.org."],
                "MX": ["10 mail.opensource.org."],
                "SOA": ["ns1.opensource.org. admin.opensource.org. 2023120303 7200 3600 1209600 86400"],
            },
            "networking.net": {
                "A": ["93.184.216.37"],
                "NS": ["ns1.networking.net.", "ns2.networking.net."],
                "MX": ["10 mail.networking.net."],
                "SOA": ["ns1.networking.net. admin.networking.net. 2023120304 7200 3600 1209600 86400"],
            },
            "university.edu": {
                "A": ["93.184.216.38"],
                "NS": ["ns1.university.edu.", "ns2.university.edu."],
                "MX": ["10 mail.university.edu."],
                "SOA": ["ns1.university.edu. admin.university.edu. 2023120305 7200 3600 1209600 86400"],
            },
            "government.gov": {
                "A": ["93.184.216.39"],
                "NS": ["ns1.government.gov.", "ns2.government.gov."],
                "MX": ["10 mail.government.gov."],
                "SOA": ["ns1.government.gov. admin.government.gov. 2023120306 7200 3600 1209600 86400"],
            },
            "techstartup.io": {
                "A": ["93.184.216.40"],
                "NS": ["ns1.techstartup.io.", "ns2.techstartup.io."],
                "MX": ["10 mail.techstartup.io."],
                "SOA": ["ns1.techstartup.io. admin.techstartup.io. 2023120307 7200 3600 1209600 86400"],
            },
            "innovators.tech": {
                "A": ["93.184.216.41"],
                "NS": ["ns1.innovators.tech.", "ns2.innovators.tech."],
                "MX": ["10 mail.innovators.tech."],
                "SOA": ["ns1.innovators.tech. admin.innovators.tech. 2023120308 7200 3600 1209600 86400"],
            },
        }

    def handle_query(self, query):
        """
        Handles the DNS query by checking the cache first and then looking up the record for the domain.
        Returns a DNS response if found or None if not found.
        """
        # First check the cache
        cached_response = self.cache.get(query)
        if cached_response:
            logging.info("Cache hit")
            return cached_response  # Return cached response if available

        # If cache miss, handle the query normally
        domain_name = self.parse_domain_name(query)
        query_type = self.parse_query_type(query)

        logging.debug(f"Handling query for domain {domain_name}, type {query_type}")

        # Check if the domain exists in the authoritative server's records
        if domain_name in self.records:
            # Check if the queried type exists for the domain
            if query_type in self.records[domain_name]:
                response = self.build_response(domain_name, query_type)
                # Store the response in cache before returning
                self.cache.store(query, response)
                return response
            else:
                logging.error(f"Query type {query_type} not found for {domain_name}")
                return self.build_error_response(query, rcode=4)  # RCODE 4: Not Implemented
        else:
            logging.error(f"Domain {domain_name} not found in authoritative records")
            return self.build_error_response(query, rcode=3)  # RCODE 3: NXDOMAIN (Non-Existent Domain)

    def build_response(self, domain_name, query_type):
        """
        Builds the DNS response based on the queried domain name and type.
        """
        # The standard DNS header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        transaction_id = 1234  # Example transaction ID
        flags = 0x8180  # Standard response, no error
        questions = 1
        answer_rrs = len(self.records[domain_name][query_type])
        authority_rrs = 0
        additional_rrs = 0

        header = struct.pack("!HHHHHH", transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)

        # Build the question section (reuse the original query)
        question_section = self.build_question_section(domain_name, query_type)

        # Build the answer section for the records
        answer_section = b""
        for record in self.records[domain_name][query_type]:
            answer_section += self.build_record(record, query_type)

        # Return the full DNS response
        return header + question_section + answer_section

    def build_record(self, record, query_type):
        """
        Builds a DNS record based on the query type (A, MX, NS, SOA, PTR).
        """
        if query_type == "A":
            # For A records, return the IPv4 address as a byte string
            ip_address = struct.unpack("!4B", bytes(map(int, record.split("."))))
            return struct.pack("!HHIH4B", 0xC00C, 1, 1, 3600, *ip_address)
        elif query_type == "NS" or query_type == "MX" or query_type == "PTR":
            # For NS, MX, PTR (Return fully qualified domain name)
            return struct.pack("!HHIH", 0xC00C, 1, 1, 3600, len(record), *record.encode())
        elif query_type == "SOA":
            # For SOA records, return the SOA data (Start of Authority)
            return struct.pack("!HHIH", 0xC00C, 6, 1, 3600, len(record), *record.encode())
        return b""  # Default to empty if no matching type found

    def build_error_response(self, query, rcode):
        """
        Constructs a DNS response with an error (e.g., NXDOMAIN).
        """
        transaction_id, _, _, _ = parse_dns_query(query)
        flags = 0x8180 | rcode  # Standard query response with the provided error code
        qd_count = 1  # One question
        an_count = 0  # No answer records
        ns_count = 0  # No authority records
        ar_count = 0  # No additional records
        header = self.build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)
        question = query[12:]  # Include the original question section
        return header + question

def parse_domain_name(self, query):
    """
    Extracts the domain name from the DNS query.
    """
    try:
        domain_name = ""
        i = 12  # Start after the header
        length = query[i]  # First length byte

        while length != 0:
            if i + length + 1 > len(query):  # Ensure bounds
                raise ValueError("Query length exceeds the buffer size while parsing the domain name.")

            domain_name += query[i + 1: i + 1 + length].decode() + "."
            i += length + 1
            length = query[i]  # Get the next length byte

        return domain_name[:-1]  # Remove trailing dot
    except (IndexError, ValueError) as e:
        logging.error(f"Failed to parse domain name from query: {e}")
        return None  # Return None or raise an exception depending on your use case


    def parse_query_type(self, query):
        """
        Extracts the query type from the DNS query (e.g., A, MX, NS, etc.).
        """
        return struct.unpack("!H", query[-4:-2])[0]

    def build_dns_header(self, transaction_id, flags, qd_count, an_count, ns_count, ar_count):
        """
        Constructs the DNS header. This can be enhanced to include more specific header building logic.
        """
        return struct.pack("!HHHHHH", transaction_id, flags, qd_count, an_count, ns_count, ar_count)

    def build_question_section(self, domain_name, query_type):
        """
        Builds the DNS question section for the query.
        """
        qname = domain_name.encode() + b'\x00'  # Null-terminated domain name
        qtype = struct.pack("!H", query_type)  # Query type as 2-byte unsigned short
        qclass = struct.pack("!H", 1)  # IN class (1)
        return qname + qtype + qclass
