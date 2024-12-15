import struct
import socket
import random
import logging
import dnslib

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


def build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count):
    """
    Builds the DNS header.
    """
    return struct.pack("!HHHHHH", transaction_id, flags, qd_count, an_count, ns_count, ar_count)

def build_dns_question(domain_name, qtype=QTYPE_A, qclass=QCLASS_IN):
    """
    Builds the DNS question section.
    """
    question = b""
    for part in domain_name.split("."):
        question += struct.pack("!B", len(part)) + part.encode()
    question += b"\x00"  # End of domain name
    question += struct.pack("!HH", qtype, qclass)  # QTYPE and QCLASS
    return question

def build_dns_query(domain_name, qtype=QTYPE_A, qclass=QCLASS_IN):
    """
    Constructs the full DNS query message, including the header and question sections.
    """
    
    if qclass != QCLASS_IN:
        raise ValueError("Invalid QCLASS. Only QCLASS_IN (1) is supported.")

    # Generate a random transaction ID
    transaction_id = random.randint(0, 65535)

    # Flags: Standard query with recursion desired (0x0100)
    flags = 0x0100

    # Set counts: 1 question, no answers, authorities, or additional records
    qd_count = 1
    an_count = 0
    ns_count = 0
    ar_count = 0

    # Build the header and question
    header = build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)
    # question = build_dns_question(domain_name, qtype, qclass)
    question = build_dns_question(domain_name, qtype, qclass)
    # Combine header and question to form the full query
    return header + question


def build_rr(name, rtype, rclass, ttl, rdata):
    """
    Builds a resource record.
    
    Parameters:
        name (str): The domain name for the record.
        rtype (int): The type of the record (e.g., 1 for A, 2 for NS).
        rclass (int): The class of the record (e.g., 1 for IN).
        ttl (int): The time-to-live value for the record.
        rdata (bytes): The record data.
    
    Returns:
        bytes: The resource record.
    """
    rr = b""
    for part in name.split("."):
        rr += struct.pack("!B", len(part)) + part.encode("utf-8")  # Encode to bytes
    rr += b"\x00"  # End of domain name
    rr += struct.pack("!HHI", rtype, rclass, ttl)  # TYPE, CLASS, TTL
    rr += struct.pack("!H", len(rdata)) + rdata  # RDLENGTH and RDATA
    return rr


def parse_dns_query(query):
    """
    Parses a DNS query to extract the transaction ID, domain name, query type (QTYPE), and query class (QCLASS).
    """
    # Ensure the query is long enough to contain a header
    if len(query) < 12:
        raise ValueError("Invalid DNS query: Too short")

    # Transaction ID is the first 2 bytes
    transaction_id = struct.unpack("!H", query[:2])[0]
    
    # Parse the domain name, which starts after the first 12 bytes (header)
    domain_parts = []
    idx = 12
    try:
        while query[idx] != 0:  # A label is terminated by a 0 byte
            length = query[idx]
            idx += 1
            if idx + length > len(query):
                raise ValueError("Invalid DNS query: Domain name length exceeds query size")
            domain_parts.append(query[idx:idx + length].decode())
            idx += length
    except IndexError:
        raise ValueError("Infvalid DNS query: Domain name parsing failed")

    domain_name = ".".join(domain_parts)
    
    # Skip the next byte before reading QTYPE and QCLASS
    idx += 1
    
    # Now that the domain is fully parsed, the next 4 bytes should be QTYPE and QCLASS
    # Ensure there's enough data for QTYPE and QCLASS (2 bytes each)
    if len(query) < idx + 4:
        raise ValueError("Invalid DNS query: Missing QTYPE or QCLASS")

    # Unpack QTYPE and QCLASS (each are 2 bytes long, so we use "!HH")
    qtype = struct.unpack("!H", query[idx:idx + 2])[0]
    qclass = struct.unpack("!H", query[idx + 2:idx + 4])[0]
    
    # Debugging output to check what values are being parsed
    # logging.debug(f"Transaction ID: {transaction_id}, Domain: {domain_name}, QTYPE: {qtype}, QCLASS: {qclass}")

    # If QCLASS is not valid, raise an error
    if qclass != 1:  # Only support IN class (1)
        logging.error(f"Invalid query: Unsupported query class {qclass}")
        raise ValueError(f"Unsupported query class: {qclass}")

    return transaction_id, domain_name, qtype, qclass




def ip_to_bytes(ip_address):
    """
    Converts a dotted-quad IPv4 address (e.g., "192.168.1.1") to 4 bytes.
    """
    return socket.inet_aton(ip_address)

def bytes_to_ip(ip_bytes):
    """
    Converts 4 bytes into a dotted-quad IPv4 address (e.g., "192.168.1.1").
    """
    return socket.inet_ntoa(ip_bytes)

def format_ns_name(name):
    """
    Formats an NS name for use in a DNS response (e.g., "ns.example.com").
    """
    formatted_name = b""
    for part in name.split("."):
        formatted_name += struct.pack("!B", len(part)) + part.encode()
    return formatted_name + b"\x00"

def validate_query(query):
    """
    Validates a DNS query for compliance with RFC standards.
    """
    if len(query) < 12:
        raise ValueError("Invalid DNS query: Query too short")

    transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
    print()
    # Ensure query type and class are supported
    if qclass != QCLASS_IN:
        raise ValueError("Unsupported query class")
    if qtype not in [QTYPE_A, QTYPE_NS, QTYPE_CNAME, QTYPE_PTR, QTYPE_MX, QTYPE_SOA]:
        raise ValueError("Unsupported query type")

    return transaction_id, domain_name, qtype, qclass

def build_error_response(transaction_id, query, rcode):
    """
    Builds a DNS response with an error code.
    """
    flags = 0x8180 | rcode  # Standard response with error code
    qd_count = 1  # Question count
    an_count = 0  # Answer count
    ns_count = 0  # Authority count
    ar_count = 0  # Additional count
    header = build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)
    question = query[12:]  # Include the original question section
    return header + question

def extract_referred_ip(response):
    """
    Extracts the referred IP address from a DNS response (Additional section).
    """
    # Locate the additional section (last part of the response)
    try:
        # Find the start of the additional section (example assumes one Authority and one Additional record)
        # Skip the header (12 bytes) + Question (domain name + 4 bytes for QTYPE/QCLASS) + Authority section
        question_end = response.find(b'\x00\x01\x00\x01') + 4  # End of Question
        additional_section = response[question_end:]

        # Locate the RDATA for the additional record
        rdata_offset = additional_section.rfind(b'\x00\x04')  # Look for A record with RDLENGTH of 4 bytes
        if rdata_offset == -1:
            raise ValueError("RDATA for A record not found in the additional section")

        # Extract the 4-byte IP address
        ip_bytes = additional_section[rdata_offset + 2: rdata_offset + 6]  # Skip the RDLENGTH
        if len(ip_bytes) != 4:
            raise ValueError(f"Invalid IP bytes length: {len(ip_bytes)} (expected 4)")

        return bytes_to_ip(ip_bytes)
    except Exception as e:
        raise ValueError(f"Failed to extract referred IP: {e}")

def bytes_to_ip(ip_bytes):
    """
    Converts 4 bytes into a dotted-quad IPv4 address (e.g., "192.168.1.1").
    """
    return socket.inet_ntoa(ip_bytes)




# def parse_dns_response(response):
#     """
#     Parse a DNS response and return a human-readable format using dnslib.
#     """
#     # Parse the DNS response using dnslib
#     dns_record = dnslib.DNSRecord.parse(response)
    
#     # Extract the transaction ID, flags, and other relevant data
#     transaction_id = dns_record.header.id
#     flags = dns_record.header.rcode
#     question_count = len(dns_record.q)
#     answer_count = len(dns_record.a)

#     # Initialize the response in human-readable format
#     human_readable = []
    
#     # Append the transaction ID and flags
#     human_readable.append(f"Transaction ID: {transaction_id}")
#     human_readable.append(f"Flags: {hex(flags)}")

#     # Process the question section
#     questions = []
#     for q in dns_record.q:
#         questions.append(f"Question: {q.qname}, Type: {q.qtype}, Class: {q.qclass}")
    
#     human_readable.append("\n".join(questions))

#     # Process the answer section
#     answers = []
#     for a in dns_record.a:
#         answers.append(f"Answer: {a.rdata}")
    
#     human_readable.append("\n".join(answers))
    
#     return "\n".join(human_readable)


# def parse_question_section(response):
#     """
#     Parse a DNS question section using dnslib.
#     """
#     dns_record = dnslib.DNSRecord.parse(response)
#     questions = []
#     for q in dns_record.q:
#         questions.append(f"Domain Name: {q.qname}, Query Type: {q.qtype}, Query Class: {q.qclass}")
    
#     return questions


# def parse_answer_section(response):
#     """
#     Parse a DNS answer section using dnslib.
#     """
#     dns_record = dnslib.DNSRecord.parse(response)
#     answers = []
#     for a in dns_record.a:
#         # Handle specific record types (e.g., A record for IPv4 address)
#         if a.rtype == 1:  # A record (IPv4)
#             ip_address = socket.inet_ntoa(a.rdata)
#             answers.append(f"Answer: {a.qname} IN A {ip_address}")
#         else:
#             answers.append(f"Answer: {a.qname} IN {a.rtype}")
    
#     return answers


# def parse_domain_name(response):
#     """
#     Parse the domain name from the DNS response using dnslib.
#     """
#     dns_record = dnslib.DNSRecord.parse(response)
#     domain_name = dns_record.q[0].qname
#     return domain_name


import struct

def extract_ip_from_answer(answer_section):
    """
    Extract the IP address from the answer section of a DNS response.

    Args:
        answer_section (str): The answer section from the DNS response (formatted as 'name IN A ip_address').

    Returns:
        str: The extracted IP address, or None if no valid A record is found.
    """
    try:
        # Split the answer section by spaces to extract the components
        parts = answer_section.split()

        # Check if the record type is A (IPv4 address)
        if len(parts) >= 4 and parts[2] == 'A':
            ip_address = parts[3]
            return ip_address
        else:
            print("Not an A record or invalid format.")
            return None
    except Exception as e:
        print(f"Error extracting IP address: {str(e)}")
        return None



def parse_dns_response(response):
    """
    Parse DNS response with enhanced error handling.
    """
    try:
        if len(response) < 12:
            raise ValueError("Response too short for DNS header")
        
        # Parse header
        header = struct.unpack("!HHHHHH", response[:12])
        transaction_id, flags, qdcount, ancount, nscount, arcount = header
        
        current_pos = 12
        questions = []
        answers = []
        
        # Parse question section
        for _ in range(qdcount):
            qname, qtype, qclass, new_pos = parse_question_section(response, current_pos)
            if qname:
                questions.append(f"{qname} TYPE{qtype} CLASS{qclass}")
            # print(questions)
            current_pos = new_pos
        
        # Parse answer section
        for _ in range(ancount):
            answer, new_pos = parse_answer_section(response, current_pos, qname)
            if answer:
                answers.append(answer)
            current_pos = new_pos
        
        return {
            'transaction_id': transaction_id,
            'flags': hex(flags),
            'questions': questions,
            'answers': answers
        }
        
    except Exception as e:
        logging.error(f"Error parsing DNS response: {str(e)}")
        return {
            'transaction_id': transaction_id if 'transaction_id' in locals() else None,
            'flags': hex(flags) if 'flags' in locals() else None,
            'questions': questions if 'questions' in locals() else [],
            'answers': answers if 'answers' in locals() else []
        }

def parse_question_section(response, start_pos):
    """
    Parse a DNS question section and return the domain name and query type/class.
    """
    # The domain name in a question section is encoded as labels (length byte + label)
    domain_name, i = parse_dns_name(response, start_pos)
    qtype, qclass = struct.unpack("!HH", response[i:i+4])
    return domain_name, qtype, qclass, i + 4


def parse_answer_section(response, offset, domain_name):
    """
    Parse DNS answer section with detailed debugging, using the domain name directly.
    """
    try:
        # print(f"\nDebug - Starting answer section parse at offset: {offset}")
        # print(f"Debug - Response bytes from offset: {response[offset:].hex()}")

        # Use the provided domain name instead of parsing it
        name = domain_name
        # print(f"Debug - Provided domain name: {name}")

        # After using the domain name, set next_offset to the given offset
        next_offset = offset

        # Ensure enough bytes for the Type/Class/TTL/Length fields
        if next_offset + 10 > len(response):
            raise ValueError(f"Response truncated. Length: {len(response)}, needed: {next_offset + 10}")

        # Parse Type, Class, TTL, and RDLENGTH
        type_class_ttl_length = response[next_offset:next_offset + 10]
        # print(f"Debug - Type/Class/TTL/Length bytes: {type_class_ttl_length.hex()}")

        # Unpack the 10 bytes to get the type, class, ttl, and rdlength
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', type_class_ttl_length)
        # print(f"Debug - Parsed fields: type={rtype}, class={rclass}, ttl={ttl}, rdlength={rdlength}")

        # Move offset past Type/Class/TTL/Length fields
        next_offset += 10  

        # Validate RDLENGTH for A records (must be 4 bytes)
        if rtype == 1:  # A record (type 1)
            if rdlength != 4:
                raise ValueError(f"Invalid A record length: {rdlength} (expected 4)")

        # Ensure enough bytes for the resource data
        if next_offset + rdlength > len(response):
            raise ValueError(f"Response truncated. Length: {len(response)}, needed: {next_offset + rdlength}")

        # Extract and format the IP address for A records (rtype 1)
        if rtype == 1 and rclass == 1:  # A record in IN class
            ip_bytes = response[next_offset:next_offset + rdlength]
            # print(f"Debug - IP bytes: {ip_bytes.hex()}")
            ip_address = '.'.join(str(b) for b in ip_bytes)
            return f"{name} IN A {ip_address}", next_offset + rdlength

        # Skip unsupported types or non-IN class
        # print(f"Debug - Unsupported record type={rtype} or class={rclass}. Skipping.")
        return None, next_offset + rdlength

    except Exception as e:
        logging.error(f"Error parsing answer section: {str(e)}", exc_info=True)
        return None, offset


def parse_dns_name(response, offset):
    """
    Parse DNS name with debug logging.
    """
    try:
        name_parts = []
        original_offset = offset
        
        # Debug output
        # print(f"Starting to parse name at offset {offset}")
        # print(f"First few bytes: {response[offset:offset+10].hex()}")
        
        while offset < len(response):
            length = response[offset]
            # print(f"Label length byte at offset {offset}: {length}")
            
            # Check for compression (0xC0)
            if length & 0xC0 == 0xC0:
                # print(f"Found compression pointer at offset {offset}")
                pointer = ((length & 0x3F) << 8) | response[offset + 1]
                # print(f"Pointer value: {pointer}")
                # Move the offset to the pointer location
                offset = pointer
                continue
            
            # Check for end of name (length byte = 0)
            if length == 0:
                break
            
            # Debug check for invalid label length
            if length > 63:
                print(f"WARNING: Invalid label length {length} at offset {offset}")
                print(f"Surrounding bytes: {response[max(0, offset - 5):offset + 5].hex()}")
                raise ValueError(f"Label length {length} exceeds maximum of 63")
            
            # Increment offset to start of the label
            offset += 1
            if offset + length > len(response):
                raise ValueError("Label extends beyond message")
            
            # Extract the label and decode it
            label = response[offset:offset + length]
            try:
                name_parts.append(label.decode('ascii'))
                # print(f"Decoded label: {name_parts[-1]}")
            except UnicodeDecodeError:
                raise ValueError("Invalid character in domain name")
            
            # Update offset to move past the label
            offset += length
            
        # Join parts to form the fully qualified domain name
        name = '.'.join(name_parts)
        # print(f"Final parsed name: {name}")
        
        # Move the offset past the null byte that ends the name
        return name, offset + 1
        
    except Exception as e:
        logging.error(f"Error parsing DNS name: {str(e)}")
        return None, offset


def parse_question_section(response, offset):
    """
    Parse DNS question section with improved error handling.
    """
    try:
        # Parse the question name
        qname, offset = parse_dns_name(response, offset)
        if qname is None:
            raise ValueError("Failed to parse question name")
        
        # Ensure we have enough bytes for qtype and qclass
        if offset + 4 > len(response):
            raise ValueError("Question section truncated")
        
        # Get question type and class
        qtype, qclass = struct.unpack("!HH", response[offset:offset + 4])
        return qname, qtype, qclass, offset + 4
        
    except Exception as e:
        logging.error(f"Error parsing question section: {str(e)}")
        return None, None, None, offset



    """
    Parse a domain name from the DNS response.
    """
    # domain_name = ""
    # i = start_pos
    # visited_pointers = visited_pointers or set()

    # while True:
    #     if i >= len(response):
    #         raise IndexError(f"Index out of range while parsing domain name at position {i}")

    #     length = response[i]
    #     i += 1

    #     # Handle pointers (compression)
    #     if length & 0xC0 == 0xC0:
    #         if i + 1 >= len(response):
    #             raise IndexError(f"Pointer exceeds response length at offset {i}")

    #         pointer = struct.unpack("!H", response[i-1:i+1])[0]
    #         pointer_offset = pointer & 0x3FFF

    #         if pointer_offset in visited_pointers:
    #             raise ValueError(f"Infinite loop detected in domain name pointers at offset {pointer_offset}")

    #         visited_pointers.add(pointer_offset)
    #         domain_name_part, _ = parse_domain_name(response, pointer_offset, visited_pointers)
    #         domain_name += domain_name_part
    #         break

    #     # End of domain name
    #     elif length == 0:
    #         i += 1  # Move past the null byte
    #         break

    #     # Regular label
    #     elif length <= 63:
    #         if i + length > len(response):
    #             raise IndexError(f"Not enough data to read label of length {length} at offset {i}")

    #         label = response[i:i + length].decode('utf-8', errors='ignore')
    #         domain_name += label + "."
    #         i += length
    #     else:
    #         raise ValueError(f"Label length exceeds maximum allowed (63): {length} at offset {i}")
    
    # return domain_name.rstrip('.'), i




