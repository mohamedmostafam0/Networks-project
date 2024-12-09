import struct
import socket
import random
import logging

# Constants for DNS message components
QTYPE_A = 1      # Query Type for A records (IPv4 addresses)
QTYPE_NS = 2     # Query Type for NS records
QTYPE_CNAME = 5  # Query Type for CNAME records
QTYPE_PTR = 12   # Query Type for PTR records
QTYPE_MX = 15    # Query Type for MX records
QTYPE_SOA = 6    # Query Type for SOA records
QCLASS_IN = 1    # Internet (IN) class



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
    """
    rr = b""
    for part in name.split("."):
        rr += struct.pack("!B", len(part)) + part.encode()
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
        raise ValueError("Invalid DNS query: Domain name parsing failed")

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


def parse_dns_response(response):
    """
    Parse a DNS response and return a human-readable format.
    """
    # Start by unpacking the DNS header (first 12 bytes)
    header = struct.unpack("!HHHHHH", response[:12])
    
    transaction_id = header[0]
    flags = header[1]
    question_count = header[2]
    answer_count = header[3]
    
    # Initialize the response
    human_readable = []
    
    # Append the transaction ID and flags in human-readable format
    human_readable.append(f"Transaction ID: {transaction_id}")
    human_readable.append(f"Flags: {hex(flags)}")
    
    # Process the question section
    current_position = 12
    questions = []
    
    for _ in range(question_count):
        domain_name, qtype, qclass, current_position = parse_question_section(response, current_position)
        questions.append(f"Question: {domain_name}, Type: {qtype}, Class: {qclass}")
    human_readable.append("\n".join(questions))
    print(human_readable)
    # Process the answer section
    answers = []
    for _ in range(answer_count):
        record, current_position = parse_answer_section(response, current_position)
        answers.append(record)
    
    human_readable.append("\n".join(answers))
    
    return "\n".join(human_readable)


def parse_question_section(response, start_pos):
    """
    Parse a DNS question section and return the domain name and query type/class.
    """
    # The domain name in a question section is encoded as labels (length byte + label)
    domain_name, i = parse_domain_name(response, start_pos)
    qtype, qclass = struct.unpack("!HH", response[i:i+4])
    return domain_name, qtype, qclass, i + 4



def parse_answer_section(response, start_pos):
    """
    Parse a DNS answer section and return the resource record in human-readable format.
    """
    # For simplicity, assume we are parsing an A record (IPv4 address)
    # In real scenarios, you'd need to handle various record types (A, MX, NS, etc.)
    i = start_pos
    domain_name_pointer = struct.unpack("!H", response[i:i+2])[0]
    i += 2
    print("domain name pointer is: ", domain_name_pointer)
    # Skip the pointer (if pointer is used, it's 0xC000 and points to the domain name in the question section)
    if domain_name_pointer >= 0xC000:
        domain_name = parse_domain_name(response, i)[0]  # Follow the pointer
    else:
        domain_name = parse_domain_name(response, i)[0]
    
    record_type, record_class, ttl, length = struct.unpack("!HHIH", response[i+2:i+10])
    i += 10
    
    # Handle A record (IPv4 address)
    if record_type == 1:  # A record type
        ip_address = socket.inet_ntoa(response[i:i+4])
        return f"Answer: {domain_name} IN A {ip_address}", i + 4
    
    # For simplicity, we handle only A records here; other record types can be added as needed
    return f"Answer: {domain_name} IN UNKNOWN", i


def parse_domain_name(response, start_pos, visited_pointers=None):
    """
    Parse a domain name from the response, handling labels and pointers.
    """
    domain_name = ""
    i = start_pos #12
    visited_pointers = visited_pointers or set()
    print("response is ", len(response))
    print("starting position is  ", start_pos)
    while True:
        if i >= len(response):
            raise IndexError("Index out of range while parsing domain name")

        length = response[i]
        print("length is ", length)
        # Handle pointers (compression)
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", response[i:i+2])[0]
            i += 2
            pointer_offset = pointer & 0x3FFF

            if pointer_offset in visited_pointers:
                raise ValueError("Infinite loop detected in domain name pointers")
            
            visited_pointers.add(pointer_offset)
            domain_name += parse_domain_name(response, pointer_offset, visited_pointers)[0]
            print(f"Parsing domain name at offset {i}, current domain: {domain_name}")
            break
        elif length == 0:  # End of domain name
            i += 1
            break
        else:  # Regular label
            print(f"Parsing domain name at offset {i}, current domain: {domain_name}")
            if i + length + 1 > len(response):
                raise IndexError("Domain name length exceeds available data.")
            
            label = response[i+1:i+1+length].decode('utf-8', errors='ignore')
            domain_name += label + "."
            i += length + 1

    return domain_name.rstrip('.'), i


