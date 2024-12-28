import struct
import logging
from name_cache import NameCache  # Import the Cache class
from utils import parse_dns_query, build_error_response

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
                "MX": ["10 mail.innovators.tech.", "20 backup.mail.innovators.tech."],
                "SOA": ["ns1.innovators.tech. admin.innovators.tech. 2023120308 7200 3600 1209600 86400"],
                "PTR": ["innovators.tech.", "reverse.innovators.tech."]
            },
        }


    def handle_name_query(self, query):
        """
        Handles the DNS query by checking the cache first and then looking up the record for the domain.
        """
        try:
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
            if not domain_name:
                return self.build_error_response(query, rcode=3)  # Invalid domain name

            # Convert qtype from numeric to string representation
            qtype_str = self.query_type_to_string(qtype)
            
            # If query type is not supported (like AAAA/28), return a "Not Implemented" response
            if qtype_str is None or qtype_str not in ['A', 'NS', 'MX', 'SOA', 'PTR', 'TXT', 'CNAME', 'MAILA', 'MAILB']:
                return self.build_error_response(query, rcode=4)  # Not Implemented

            if domain_name in self.records:
                if qtype_str in self.records[domain_name]:
                    response = self.build_response(query, domain_name, qtype_str)
                    self.cache.store(response)
                    return response
                else:
                    return self.build_error_response(query, rcode=4)
            else:
                return self.build_error_response(query, rcode=3)

        except Exception as e:
            logging.error(f"Error handling query: {e}")
            return self.build_error_response(query, rcode=2)  # Server failure


    def build_response(self, query, domain_name, query_type):
        """
        Builds the DNS response with detailed debugging.
        """
        try:
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query)

            # Header section
            flags = 0x8180  # Standard query response (QR=1, AA=0, RCODE=0)
            questions = 1
            answers = len(self.records[domain_name].get(query_type, []))
            authority_rrs = 0
            additional_rrs = 0

            header = struct.pack("!HHHHHH", 
                            transaction_id, 
                            flags, 
                            questions, 
                            answers, 
                            authority_rrs, 
                            additional_rrs)

            # Question section
            question = b''
            for label in domain_name.split('.'):
                question += bytes([len(label)]) + label.encode('ascii')
            question += b'\x00'  # Terminating byte
            question += struct.pack("!HH", qtype, qclass)  # QTYPE=A(1), QCLASS=IN(1)


            # Answer section
            answer = b''
            if query_type in ["A", "NS", "MX", "CNAME", "PTR", "TXT", "SOA", "MG", "MR", "HINFO", "MINFO", "MAILB", "MAILA"] and domain_name in self.records:
                for record in self.records[domain_name].get(query_type, []):
                    answer += b'\xc0\x0c'  # Compression pointer to domain name
                    answer += struct.pack("!HHI", getattr(self, f"QTYPE_{query_type}"), 1, 3600)  # TYPE, CLASS, TTL

                    if query_type == "A":
                        answer += struct.pack("!H", 4)  # RDLENGTH
                        answer += struct.pack("!4B", *map(int, record.split('.')))
                    elif query_type == "TXT":
                        answer += struct.pack("!H", len(record) + 1)  # RDLENGTH
                        answer += struct.pack("!B", len(record)) + record.encode('ascii')
                    elif query_type in ["CNAME", "NS", "PTR"]:
                        answer += struct.pack("!H", len(record) + 1)  # RDLENGTH
                        for label in record.split('.'):  # Encode domain name
                            answer += bytes([len(label)]) + label.encode('ascii')
                        answer += b'\x00'
                    elif query_type in ["HINFO"]:
                        cpu, os = record
                        answer += struct.pack("!H", len(cpu) + len(os) + 2)
                        answer += struct.pack("!B", len(cpu)) + cpu.encode('ascii')
                        answer += struct.pack("!B", len(os)) + os.encode('ascii')
                    elif query_type in ["MG", "MR", "MAILB", "MAILA"]: #cacheee
                        answer += struct.pack("!H", len(record) + 1)
                        answer += struct.pack("!B", len(record)) + record.encode('ascii')
                    elif query_type == "MINFO":
                        rmailbx, emailbx = record
                        answer += struct.pack("!H", len(rmailbx) + len(emailbx) + 2)
                        answer += struct.pack("!B", len(rmailbx)) + rmailbx.encode('ascii')
                        answer += struct.pack("!B", len(emailbx)) + emailbx.encode('ascii')
                    elif query_type == "NULL":
                        answer += struct.pack("!H", 0)  # RDLENGTH is 0
                    elif query_type == "WKS": # Not support asln
                        answer += struct.pack("!H", len(record) + 1)
                        answer += struct.pack("!B", len(record)) + record.encode('ascii')

            # Full response
            response = header + question + answer
            return response
        except Exception as e:
            logging.error(f"Error building DNS response: {e}")
            return None

        #     # Answer section


        #     answer = b''
        #     if query_type == "A" and domain_name in self.records:
        #         for ip_address in self.records[domain_name][query_type]:
        #             answer += b'\xc0\x0c'  # Compression pointer to domain name
        #             answer += struct.pack("!HH", 
        #                             1,    # TYPE A
        #                             1)    # CLASS IN
        #             answer += struct.pack("!I", 3600)  # TTL
        #             answer += struct.pack("!H", 4)     # RDLENGTH (4 for IPv4)
        #             ip_parts = [int(part) for part in ip_address.split('.')]
        #             answer += bytes(ip_parts)          # RDATA (IP address


        #     elif query_type == "MX" and domain_name in self.records:
        #         for mail_server, priority in self.records[domain_name][query_type]:
        #             fixed_fields = struct.pack("!HHIH", 
        #                                     15,     # TYPE: MX
        #                                     1,      # CLASS: IN
        #                                     3600,   # TTL
        #                                     len(mail_server) + 2)  # RDLENGTH: len(mail_server) + 2 bytes for priority
        #             answer += fixed_fields
                    
        #             # Priority field (2 bytes)
        #             answer += struct.pack("!H", priority)
                    
        #             # Mail server field (string, encoded)
        #             answer += bytes([len(mail_server)]) + mail_server.encode('ascii')

        #     elif query_type == "NS" and domain_name in self.records:
        #         for ns_server in self.records[domain_name][query_type]:
        #             fixed_fields = struct.pack("!HHIH", 
        #                                     2,      # TYPE: NS
        #                                     1,      # CLASS: IN
        #                                     3600,   # TTL
        #                                     len(ns_server) + 2)  # RDLENGTH: length of NS server
        #             answer += fixed_fields
                    
        #             # NS record (server name)
        #             answer += bytes([len(ns_server)]) + ns_server.encode('ascii')

        #     elif query_type == "CNAME" and domain_name in self.records:
        #         for cname in self.records[domain_name][query_type]:
        #             fixed_fields = struct.pack("!HHIH", 
        #                                     5,      # TYPE: CNAME
        #                                     1,      # CLASS: IN
        #                                     3600,   # TTL
        #                                     len(cname) + 1)  # RDLENGTH: length of CNAME
        #             answer += fixed_fields
                    
        #             # CNAME record (canonical name)
        #             answer += bytes([len(cname)]) + cname.encode('ascii')

        #     elif query_type == "SOA" and domain_name in self.records:
        #         # SOA record fields: primary NS, hostmaster, serial, refresh, retry, expire, minimum TTL
        #         soa_fields = self.records[domain_name][query_type]
        #         fixed_fields = struct.pack("!HHIH", 
        #                                     6,      # TYPE: SOA
        #                                     1,      # CLASS: IN
        #                                     3600,   # TTL
        #                                     20)     # RDLENGTH: sum of the field lengths
        #         answer += fixed_fields

        #         # SOA record fields (in order)
        #         for field in soa_fields:
        #             if isinstance(field, int):
        #                 answer += struct.pack("!I", field)  # Integer values (serial, refresh, retry, expire, etc.)
        #             else:
        #                 answer += bytes([len(field)]) + field.encode('ascii')  # String fields (NS, hostmaster)

        #     elif query_type == "PTR" and domain_name in self.records:
        #         for ptr_record in self.records[domain_name][query_type]:
        #             fixed_fields = struct.pack("!HHIH", 
        #                                     12,     # TYPE: PTR
        #                                     1,      # CLASS: IN
        #                                     3600,   # TTL
        #                                     len(ptr_record) + 1)  # RDLENGTH: length of PTR record
        #             answer += fixed_fields
                    
        #             # PTR record (reverse DNS)
        #             answer += bytes([len(ptr_record)]) + ptr_record.encode('ascii')

        #     # Full response
        #     # logging.info(f"header is {header}, question is {question}, answer is {answer}")
        #     response = header + question + answer
        #     return response

        # except Exception as e:
        #     logging.error(f"Error building DNS response: {e}")
        #     return None

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
        Extracts the query type from the DNS query and maps it to its string equivalent.
        """
        if len(query) < 4:
            logging.error("Query too short to extract query type")
            return None

        # Extract the query type (last 4-2 bytes for qtype)
        query_type_num = struct.unpack("!H", query[-4:-2])[0]
        # logging.debug(f"Extracted numeric query type: {query_type_num}")

        # Map numeric query type to its string representation
        query_type_map = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            33: "SRV",
        }

        # Log if the query type is unmapped
        if query_type_num not in query_type_map:
            logging.error(f"Unmapped query type: {query_type_num}")
        return query_type_map.get(query_type_num, None)

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
        """
        Saves the current DNS records into JSON master files.
        """
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        for domain, records in self.records.items():
            file_name = f"{output_dir}/{domain.replace('.', '_')}.json"
            try:
                with open(file_name, 'w') as file:
                    json.dump({"domain": domain, "records": records}, file, indent=4)
                logging.info(f"Master file saved: {file_name}")
            except Exception as e:
                logging.error(f"Failed to save master file {file_name}: {e}")