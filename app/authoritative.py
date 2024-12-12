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


    def handle_name_query(self, query):
        """
        Handles the DNS query by checking the cache first and then looking up the record for the domain.
        Returns a DNS response if found or None if not found.
        """
        cached_response = self.cache.get(query)
        if cached_response:
            logging.info("Cache hit")
            return cached_response

        domain_name = self.parse_domain_name(query)
        if not domain_name:
            return self.build_error_response(query, rcode=3)  # Invalid domain name

        query_type = self.parse_query_type(query)

        logging.debug(f"Handling query for domain {domain_name}, type {query_type}")

        if domain_name in self.records:
            if query_type in self.records[domain_name]:
                response = self.build_response(domain_name, query_type)
                self.cache.store(query, response)
                return response
            else:
                logging.error(f"Query type {query_type} not found for {domain_name}")
                return self.build_error_response(query, rcode=4)
        else:
            logging.error(f"Domain {domain_name} not found in authoritative records")
            return self.build_error_response(query, rcode=3)


    def build_response(self, domain_name, query_type):
        """
        Builds the DNS response with detailed debugging.
        """
        try:
            # Header section
            transaction_id = 1234
            flags = 0x8180
            questions = 1
            answers = len(self.records[domain_name][query_type])
            authority_rrs = 0
            additional_rrs = 0

            header = struct.pack("!HHHHHH", 
                            transaction_id, 
                            flags, 
                            questions, 
                            answers, 
                            authority_rrs, 
                            additional_rrs)
            print(f"Debug - Header bytes: {header.hex()}")

            # Question section
            question = b''
            for label in domain_name.split('.'):
                question += bytes([len(label)]) + label.encode('ascii')
            question += b'\x00'  # Terminating byte
            question += struct.pack("!HH", 1, 1)  # QTYPE=A(1), QCLASS=IN(1)
            print(f"Debug - Question bytes: {question.hex()}")

            # Answer section
            answer = b''
            if query_type == "A" and domain_name in self.records:
                for ip_address in self.records[domain_name][query_type]:
                    print(f"Debug - Processing IP: {ip_address}")
                    
                    # Compression pointer
                    pointer = struct.pack("!H", 0xC00C)
                    answer += pointer
                    print(f"Debug - Compression pointer bytes: {pointer.hex()}")
                    
                    # Type, Class, TTL, RDLength
                    fixed_fields = struct.pack("!HHIH", 
                                            1,      # TYPE: A
                                            1,      # CLASS: IN
                                            3600,   # TTL
                                            4)      # RDLENGTH: 4 bytes
                    answer += fixed_fields
                    print(f"Debug - Fixed fields bytes: {fixed_fields.hex()}")
                    
                    # IP address bytes
                    ip_parts = [int(part) for part in ip_address.split('.')]
                    ip_bytes = bytes(ip_parts)
                    answer += ip_bytes
                    print(f"Debug - IP address bytes: {ip_bytes.hex()}")

            print(f"Debug - Full answer bytes: {answer.hex()}")
            response = header + question + answer
            print(f"Debug - Full response bytes: {response.hex()}")
            
            return response

        except Exception as e:
            logging.error(f"Error in build_response: {str(e)}", exc_info=True)
            return None

    def pack_domain_name(self, domain):
        """
        Packs a domain name into DNS wire format.
        """
        result = b''
        for label in domain.split('.'):
            if label:  # Skip empty labels
                length = len(label)
                result += struct.pack('!B', length) + label.encode()
        return result + b'\x00'  # Terminate with null byte



    def build_record(self, record, query_type):
        """
        Builds a DNS record with proper formatting.
        """
        if query_type == "A":
            # Properly format A record
            ip_parts = [int(x) for x in record.split(".")]
            return struct.pack("!HHIH4B", 0xC00C, 1, 1, 3600, *ip_parts)
    


    # def build_record(self, record, query_type):
    #     """
    #     Builds a DNS record based on the query type (A, MX, NS, SOA, PTR).
    #     """
    #     if query_type == "A":
    #         # For A records, return the IPv4 address as a byte string
    #         ip_address = struct.unpack("!4B", bytes(map(int, record.split("."))))
    #         return struct.pack("!HHIH4B", 0xC00C, 1, 1, 3600, *ip_address)
    #     elif query_type == "NS" or query_type == "MX" or query_type == "PTR":
    #         # For NS, MX, PTR (Return fully qualified domain name)
    #         return struct.pack("!HHIH", 0xC00C, 1, 1, 3600, len(record), *record.encode())
    #     elif query_type == "SOA":
    #         # For SOA records, return the SOA data (Start of Authority)
    #         return struct.pack("!HHIH", 0xC00C, 6, 1, 3600, len(record), *record.encode())
    #     return b""  # Default to empty if no matching type found

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
            return None

    def parse_query_type(self, query):
        """
        Extracts the query type from the DNS query (e.g., 1 for A, 2 for NS, etc.) and maps it to its string equivalent.
        """
        # Map of numeric query types to their string representations
        query_type_map = {
            1: "A",     # Host Address
            2: "NS",    # Name Server
            5: "CNAME", # Canonical Name
            15: "MX",   # Mail Exchange
            33: "PTR",  # Pointer
            6: "SOA",   # Start of Authority
        }

        query_type_num = struct.unpack("!H", query[-4:-2])[0]  # Get the query type number from the query

        # Return the mapped query type, or None if the type is unknown
        return query_type_map.get(query_type_num, None)


    def build_dns_header(self, transaction_id, flags, qd_count, an_count, ns_count, ar_count):
        """
        Constructs the DNS header. This can be enhanced to include more specific header building logic.
        """
        return struct.pack("!HHHHHH", transaction_id, flags, qd_count, an_count, ns_count, ar_count)

    def query_type_to_int(self, qtype):
        """
        Convert query type string to number.
        """
        type_map = {
            'A': 1,
            'NS': 2,
            'CNAME': 5,
            'SOA': 6,
            'PTR': 12,
            'MX': 15
        }
        return type_map.get(qtype, 1)  # Default to A record type

        return query_type_map.get(query_type, None)

    def build_question_section(self, domain_name, query_type):
        """
        Builds the DNS question section for the query.
        Converts the query type string to an integer and builds the section.
        """
        # If query_type is a string, convert it to integer
        if isinstance(query_type, str):
            query_type = self.query_type_to_int(query_type)
            if query_type is None:
                raise ValueError(f"Invalid query type: {query_type}")
        
        qname = domain_name.encode() + b'\x00'  # Null-terminated domain name
        qtype = struct.pack("!H", query_type)  # Query type as 2-byte unsigned short
        qclass = struct.pack("!H", 1)  # IN class (1)
        return qname + qtype + qclass
