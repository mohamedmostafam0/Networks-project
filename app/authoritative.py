import struct
import logging
from name_cache import NameCache  # Import the Cache class
from utils import parse_dns_query, build_error_response
import os


# Set up logging
QTYPE_A = 1       # A host address (IPv4 addresses)
QTYPE_NS = 2      
QTYPE_MD = 3      
QTYPE_MF = 4      
QTYPE_CNAME = 5   # The canonical name for an alias
QTYPE_SOA = 6     # Marks the start of a zone of authority
QTYPE_MB = 7     
QTYPE_MG = 8     
QTYPE_MR = 9     
QTYPE_NULL = 10     
QTYPE_WKS = 11     
QTYPE_PTR = 12    # A domain name pointer (reverse DNS)
QTYPE_HINFO = 13  # Host information
QTYPE_MINFO = 14  # Mailbox or mail list information
QTYPE_MX = 15     # Mail exchange
QTYPE_TXT = 16    # Text strings (TXT records)
QTYPE_AXFR = 252  
QTYPE_MAILB = 253  
QTYPE_MAILA = 254  

logging.basicConfig(level=logging.DEBUG)

class AuthoritativeServer: 
    def __init__(self, cache: NameCache):
        """
        Initializes the authoritative DNS server with some predefined DNS records.
        """
        self.cache = cache  # Use the passed-in cache instance
        self.records = {
            "example.com": {
                "A": ["93.184.216.34"],
                "NS": ["ns1.example.com.", "ns2.example.com."],
                "MX": ["10 mail.example.com.", "20 backup.mail.example.com."],
                "SOA": ["ns1.example.com. admin.example.com. 2023120301 7200 3600 1209600 86400"],
                "PTR": ["example.com."],
                "TXT": ["v=spf1 include:_spf.example.com ~all"],
                "CNAME": ["alias.example.com."],
                "MG": ["mailgroup@example.com"],
                "MR": ["mailrename@example.com"],
                "NULL": [""],
                "WKS": ["93.184.216.34"],
                "HINFO": ["Intel i7", "Ubuntu Linux"],
                "MINFO": ["admin@example.com", "errors@example.com"],
                "MAILB": ["mailbackup@example.com"],
                "MAILA": ["mailalternate@example.com"],
            },

            "mywebsite.com": {
                "A": ["93.184.216.35", "93.184.216.36"],
                "NS": ["ns1.mywebsite.com.", "ns2.mywebsite.com."],
                "MX": ["10 mail.mywebsite.com.", "20 backup.mail.mywebsite.com."],
                "SOA": ["ns1.mywebsite.com. admin.mywebsite.com. 2023120302 7200 3600 1209600 86400"],
                "PTR": ["mywebsite.com.", "reverse.mywebsite.com."]
            },
            "opensource.org": {
                "A": ["93.184.216.36", "93.184.216.37"],
                "NS": ["ns1.opensource.org.", "ns2.opensource.org."],
                "MX": ["10 mail.opensource.org.", "20 backup.mail.opensource.org."],
                "SOA": ["ns1.opensource.org. admin.opensource.org. 2023120303 7200 3600 1209600 86400"],
                "PTR": ["opensource.org.", "reverse.opensource.org."]
            },
            "networking.net": {
                "A": ["93.184.216.37", "93.184.216.38"],
                "NS": ["ns1.networking.net.", "ns2.networking.net."],
                "MX": ["10 mail.networking.net.", "20 backup.mail.networking.net."],
                "SOA": ["ns1.networking.net. admin.networking.net. 2023120304 7200 3600 1209600 86400"],
                "PTR": ["networking.net."],
                "TXT": ["v=spf1 include:_spf.networking.net ~all"],
                "CNAME": ["alias.networking.net."],
                "MG": ["mailgroup@networking.net"],
                "MR": ["mailrename@networking.net"],
                "NULL": [""],
                "WKS": ["93.184.216.37"],
                "HINFO": ["Intel i7", "Ubuntu Linux"],
                "MINFO": ["admin@networking.net", "errors@networking.net"],
                "MAILB": ["mailbackup@networking.net"],
                "MAILA": ["mailalternate@networking.net"],
            },
            "university.edu": {
                "A": ["93.184.216.38", "93.184.216.39"],
                "NS": ["ns1.university.edu.", "ns2.university.edu."],
                "MX": ["10 mail.university.edu.", "20 backup.mail.university.edu."],
                "SOA": ["ns1.university.edu. admin.university.edu. 2023120305 7200 3600 1209600 86400"],
                "PTR": ["university.edu."],
                "TXT": ["v=spf1 include:_spf.university.edu ~all"],
                "CNAME": ["alias.university.edu."],
                "MG": ["mailgroup@university.edu"],
                "MR": ["mailrename@university.edu"],
                "NULL": [""],
                "WKS": ["93.184.216.38"],
                "HINFO": ["Intel i7", "Ubuntu Linux"],
                "MINFO": ["admin@university.edu", "errors@university.edu"],
                "MAILB": ["mailbackup@university.edu"],
                "MAILA": ["mailalternate@university.edu"],
            },
            "government.gov": {
                "A": ["93.184.216.39", "93.184.216.40"],
                "NS": ["ns1.government.gov.", "ns2.government.gov."],
                "MX": ["10 mail.government.gov.", "20 backup.mail.government.gov."],
                "SOA": ["ns1.government.gov. admin.government.gov. 2023120306 7200 3600 1209600 86400"],
                "PTR": ["government.gov.", "reverse.government.gov."]
            },
            "techstartup.io": {
                "A": ["93.184.216.40", "93.184.216.41"],
                "NS": ["ns1.techstartup.io.", "ns2.techstartup.io."],
                "MX": ["10 mail.techstartup.io.", "20 backup.mail.techstartup.io."],
                "SOA": ["ns1.techstartup.io. admin.techstartup.io. 2023120307 7200 3600 1209600 86400"],
                "PTR": ["techstartup.io.", "reverse.techstartup.io."]
            },
            "innovators.tech": {
                "A": ["93.184.216.41", "93.184.216.42"],
                "NS": ["ns1.innovators.tech.", "ns2.innovators.tech."],
                "MX": ["10 mail.innovators.tech."],
                "SOA": ["ns1.innovators.tech. admin.innovators.tech. 2023120308 7200 3600 1209600 86400"],
                "PTR": ["innovators.tech.", "reverse.innovators.tech."]
            },
        }


    def handle_name_query(self, query):
        """
        Handles the DNS query by checking the cache first and then looking up the record for the domain.
        """
        try:
            transaction_id, domain_name, qtype, _ = parse_dns_query(query)
            if not domain_name:
                return build_error_response(query, rcode=3)  # Invalid domain name

            # Convert qtype from numeric to string representation
            qtype_str = self.query_type_to_string(qtype)
            
            # If query type is not supported (like AAAA/28), return a "Not Implemented" response
            if qtype_str is None or qtype_str not in ['A', 'NS', 'MX', 'SOA', 'PTR', 'TXT', 'CNAME', 'MAILA', 'MAILB']:
                return build_error_response(query, rcode=4)  # Not Implemented

            if domain_name in self.records:
                if qtype_str in self.records[domain_name]:
                    response = self.build_response(query)
                    self.cache.store(response)
                    return response
                else:
                    return build_error_response(query, rcode=4)
            else:
                return build_error_response(query, rcode=3)

        except Exception as e:
            logging.error(f"Error handling query: {e}")
            return build_error_response(query, rcode=2)  # Server failure


    def build_response(self, query):
        """
        Builds the DNS response with detailed debugging for various query types.
        """
        try:
            # Parse the DNS query
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
            # logging.info(f"Query: {query}, domain: {domain_name}, qtype: {qtype}, qclass: {qclass}")

            # Check if the domain and requested record type exist
            record_type = self.query_type_to_string(qtype)
            if not record_type or domain_name not in self.records or record_type not in self.records[domain_name]:
                return build_error_response(query, rcode=3)  # NXDOMAIN

            # Header Section
            flags = 0x8180  # Standard query response (QR=1, AA=1, RCODE=0)
            questions = 1
            answers = len(self.records[domain_name][record_type])
            authority_rrs = 0
            additional_rrs = 0
            header = self.build_dns_header(transaction_id, flags, questions, answers, authority_rrs, additional_rrs)
            # logging.debug(f"Header: {header}")

            # Question Section
            question = b''.join(
                bytes([len(label)]) + label.encode('ascii') for label in domain_name.split('.')
            ) + b'\x00'
            question += struct.pack("!HH", qtype, qclass)
            # logging.debug(f"Question: {question}")

            # Answer Section
            answer = b''
            domain_offsets = {domain_name: 12}  # Domain offsets for compression pointers
            current_length = len(header) + len(question)

            for record in self.records[domain_name][record_type]:
                compressed_name, current_length = self.encode_domain_name_with_compression(domain_name, domain_offsets, current_length)
                answer += compressed_name

                if record_type == "A":
                    # IPv4 address
                    answer += struct.pack("!HHI", QTYPE_A, qclass, 3600)  # TYPE, CLASS, TTL
                    answer += struct.pack("!H", 4)  # RDLENGTH
                    answer += bytes(map(int, record.split('.')))  # RDATA (IPv4 address)

                elif record_type == "MX":
                    # Mail exchange record
                    priority, mail_server = record.split(' ', 1)
                    
                    # Encode the mail server's domain name with compression
                    mail_server_rdata, current_length = self.encode_domain_name_with_compression(mail_server, domain_offsets, current_length)
                    
                    # Construct the RDATA: priority + encoded domain name
                    rdata = struct.pack("!H", int(priority)) + mail_server_rdata
                    
                    # Log the RDATA details for debugging
                    # logging.debug(f"RDATA for MX record: {rdata} with length {len(rdata)}")
                    
                    # Add the MX record to the answer section
                    answer += struct.pack("!HHIH", QTYPE_MX, qclass, 3600, len(rdata)) + rdata
                    
                    # logging.debug(f"Answer after adding MX record: {answer} with length {len(answer)}")

                elif record_type == "NS":
                    # Name server
                    rdata, current_length = self.encode_domain_name_with_compression(record, domain_offsets, current_length)
                    answer += struct.pack("!HHIH", QTYPE_NS, qclass, 3600, len(rdata)) + rdata

                elif record_type == "CNAME":
                    # Canonical name
                    rdata, current_length = self.encode_domain_name_with_compression(record, domain_offsets, current_length)
                    answer += struct.pack("!HHIH", QTYPE_CNAME, qclass, 3600, len(rdata)) + rdata

                elif record_type == "SOA":
                    # Split the SOA record into components
                    primary_ns, admin_email, serial, refresh, retry, expire, min_ttl = record.split(' ')
                    primary_ns_rdata, current_length = self.encode_domain_name_with_compression(primary_ns, domain_offsets, current_length)
                    admin_email_rdata, current_length = self.encode_domain_name_with_compression(admin_email, domain_offsets, current_length)
                    rdata = primary_ns_rdata + admin_email_rdata
                    rdata += struct.pack("!IIIII", int(serial), int(refresh), int(retry), int(expire), int(min_ttl))
                    answer += struct.pack("!HHIH", QTYPE_SOA, qclass, 3600, len(rdata)) + rdata

                elif record_type == "PTR":
                    # Pointer (reverse DNS)
                    rdata, current_length = self.encode_domain_name_with_compression(record, domain_offsets, current_length)
                    answer += struct.pack("!HHIH", QTYPE_PTR, qclass, 3600, len(rdata)) + rdata

                elif record_type == "TXT":
                    # Text record
                    rdata = bytes([len(record)]) + record.encode('ascii')
                    answer += struct.pack("!HHIH", QTYPE_TXT, qclass, 3600, len(rdata)) + rdata

            # Full Response
            response = header + question + answer
            # logging.debug(f"answer is {answer}")
            # logging.debug(f"Header size: {len(header)}, Question size: {len(question)}, Answer size: {len(answer)}, Total: {len(response)}")
            # logging.info(f"Response built: {response}")
            return response

        except Exception as e:
            logging.error(f"Error building DNS response: {e}")
            return build_error_response(query, rcode=2)  # Server failure



    # def pack_domain_name(self, domain):
    #     """
    #     Packs a domain name into DNS wire format.
    #     """
    #     result = b''
    #     for label in domain.split('.'):
    #         if label:  # Skip empty labels
    #             length = len(label)
    #             result += struct.pack('!B', length) + label.encode()
    #     return result + b'\x00'  # Terminate with null byte

    # def build_record(self, record, query_type):
    #     """
    #     Builds a DNS record with proper formatting.
    #     """
    #     if query_type == "A":
    #         # Properly format A record
    #         ip_parts = [int(x) for x in record.split(".")]
    #         return struct.pack("!HHIH4B", 0xC00C, 1, 1, 3600, *ip_parts)
    

    # def parse_domain_name(self, query):
    #     """
    #     Extracts the domain name from the DNS query.
    #     """
    #     try:
    #         domain_name = ""
    #         i = 12  # Start after the header
    #         length = query[i]  # First length byte

    #         while length != 0:
    #             if i + length + 1 > len(query):  # Ensure bounds
    #                 raise ValueError("Query length exceeds the buffer size while parsing the domain name.")

    #             domain_name += query[i + 1: i + 1 + length].decode() + "."
    #             i += length + 1
    #             length = query[i]  # Get the next length byte

    #         return domain_name[:-1]  # Remove trailing dot
    #     except (IndexError, ValueError) as e:
    #         logging.error(f"Failed to parse domain name from query: {e}")
    #         return None

    # def parse_query_type(self, query):
    #     """
    #     Extracts the query type from the DNS query and maps it to its string equivalent.
    #     """
    #     if len(query) < 4:
    #         logging.error("Query too short to extract query type")
    #         return None

    #     # Extract the query type (last 4-2 bytes for qtype)
    #     query_type_num = struct.unpack("!H", query[-4:-2])[0]
    #     # logging.debug(f"Extracted numeric query type: {query_type_num}")

    #     # Map numeric query type to its string representation
    #     query_type_map = {
    #         1: "A",
    #         2: "NS",
    #         5: "CNAME",
    #         6: "SOA",
    #         12: "PTR",
    #         15: "MX",
    #         16: "TXT",
    #         33: "SRV",
    #     }

    #     # Log if the query type is unmapped
    #     if query_type_num not in query_type_map:
    #         logging.error(f"Unmapped query type: {query_type_num}")
    #     return query_type_map.get(query_type_num, None)

    def build_dns_header(self, transaction_id, flags, qd_count, an_count, ns_count, ar_count):
        """
        Constructs the DNS header. This can be enhanced to include more specific header building logic.
        """
        return struct.pack("!HHHHHH", transaction_id, flags, qd_count, an_count, ns_count, ar_count)

    def query_type_to_string(self, qtype_num):
        """
        Convert numeric query type to its string representation.
        Returns None if the query type is not recognized.
        """
        query_type_map = {
            QTYPE_A: "A",
            QTYPE_NS: "NS",
            QTYPE_MD: "MD",
            QTYPE_MF: "MF",
            QTYPE_CNAME: "CNAME",
            QTYPE_SOA: "SOA",
            QTYPE_MB: "MB",
            QTYPE_MG: "MG",
            QTYPE_MR: "MR",
            QTYPE_NULL: "NULL",
            QTYPE_WKS: "WKS",
            QTYPE_PTR: "PTR",
            QTYPE_HINFO: "HINFO",
            QTYPE_MINFO: "MINFO",
            QTYPE_MX: "MX",
            QTYPE_TXT: "TXT",
            QTYPE_AXFR: "AXFR",
            QTYPE_MAILB: "MAILB",
            QTYPE_MAILA: "MAILA",
        }
        return query_type_map.get(qtype_num, None)

    def query_type_to_int(self, qtype):
        """
        Convert query type string to number.
        """
        type_map = {
            "A": self.QTYPE_A,
            "NS": self.QTYPE_NS,
            "MD": self.QTYPE_MD,
            "MF": self.QTYPE_MF,
            "CNAME": self.QTYPE_CNAME,
            "SOA": self.QTYPE_SOA,
            "MB": self.QTYPE_MB,
            "MG": self.QTYPE_MG,
            "MR": self.QTYPE_MR,
            "NULL": self.QTYPE_NULL,
            "WKS": self.QTYPE_WKS,
            "PTR": self.QTYPE_PTR,
            "HINFO": self.QTYPE_HINFO,
            "MINFO": self.QTYPE_MINFO,
            "MX": self.QTYPE_MX,
            "TXT": self.QTYPE_TXT,
            "AXFR": self.QTYPE_AXFR,
            "MAILB": self.QTYPE_MAILB,
            "MAILA": self.QTYPE_MAILA,
        }
        return type_map.get(qtype, None)
    
    def encode_domain_name_with_compression(self, domain_name, domain_offsets, current_length):
        """
        Encodes a domain name, using compression pointers where possible.

        Parameters:
        - domain_name (str): The domain name to encode.
        - domain_offsets (dict): A dictionary mapping domain names to their positions.
        - current_length (int): The current length of the message.

        Returns:
        - bytes: The encoded domain name.
        - int: The updated current length of the message.
        """
        try:
            # logging.debug(f"Encoding domain name: {domain_name}")
            # logging.debug(f"Current domain offsets: {domain_offsets}")
            # logging.debug(f"Current message length: {current_length}")

            if domain_name in domain_offsets:
                # Use a compression pointer if the domain was already encoded
                pointer = domain_offsets[domain_name]
                # logging.debug(f"Domain name '{domain_name}' already encoded at offset {pointer}. Using compression pointer.")
                compressed_pointer = struct.pack("!H", 0xC000 | pointer)
                # logging.debug(f"Compressed pointer: {compressed_pointer}")
                return compressed_pointer, current_length
            else:
                # Encode the domain name fully and store its position
                encoded_name = b''.join(
                    bytes([len(label)]) + label.encode('ascii') for label in domain_name.split('.')
                )
                if not encoded_name.endswith(b'\x00'):  # Ensure only one null byte for termination
                    encoded_name += b'\x00'
                # logging.debug(f"Encoded domain name before storing: {encoded_name}")
                domain_offsets[domain_name] = current_length
                return encoded_name, current_length + len(encoded_name)
        except Exception as e:
            logging.error(f"Error encoding domain name '{domain_name}': {e}")
            raise

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


        #master file

    def save_master_files(self, output_dir="master_files"):
        os.makedirs(output_dir, exist_ok=True)
        for domain, records in self.records.items():
            file_name = f"{output_dir}/{domain.replace('.', '_')}.zone"
            try:
                with open(file_name, 'w') as file:
                    file.write(f"$ORIGIN {domain}.\n$TTL 3600\n")
                    for rtype, rdata_list in records.items():
                        for rdata in rdata_list:
                            if rtype == "SOA":
                                primary_ns, admin_email, serial, refresh, retry, expire, min_ttl = rdata.split(' ')
                                file.write(f"{domain} IN SOA {primary_ns} {admin_email} {serial} {refresh} {retry} {expire} {min_ttl}\n")
                            elif rtype == "MX":
                                priority, mail_server = rdata.split(' ', 1)
                                file.write(f"{domain} IN MX {priority} {mail_server}\n")
                            else:
                                file.write(f"{domain} IN {rtype} {rdata}\n")
                logging.info(f"Master file saved: {file_name}")
            except Exception as e:
                logging.error(f"Failed to save master file {file_name}: {e}")
                


