import struct
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# DNS header fields
HEADER_FORMAT = "!HHHHHH"
QUESTION_FORMAT = "!HH"
ANSWER_FORMAT = "!HHIH"
MAX_DNS_PACKET_SIZE = 512

# DNS RCODE values
RCODES = {
    0: "NoError",
    1: "FormatError",
    2: "ServerFailure",
    3: "NameError",
    4: "NotImplemented",
    5: "Refused",
    6: "YxDomain",
    7: "YxRRSet",
    8: "NxRRSet",
    9: "NotAuth",
    10: "NotZone"
}

def build_header(transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs):
    """
    Builds the DNS header.
    """
    return struct.pack(HEADER_FORMAT, transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)

def parse_header(data):
    """
    Parses the DNS header from the raw data.
    """
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack(HEADER_FORMAT, data[:12])
    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "questions": questions,
        "answer_rrs": answer_rrs,
        "authority_rrs": authority_rrs,
        "additional_rrs": additional_rrs
    }

def build_question(domain_name, query_type, query_class):
    """
    Builds the DNS question section.
    """
    question = b""
    for part in domain_name.split("."):
        question += struct.pack("!B", len(part)) + part.encode()
    question += b"\x00"  # Null byte to indicate the end of the domain name
    question += struct.pack(QUESTION_FORMAT, query_type, query_class)
    return question

def parse_question(data):
    """
    Parses the DNS question section from the raw data.
    """
    i = 0
    labels = []
    while data[i] != 0:
        length = data[i]
        labels.append(data[i+1:i+1+length].decode())
        i += length + 1
    domain_name = ".".join(labels)
    query_type, query_class = struct.unpack(QUESTION_FORMAT, data[i+1:i+5])
    return domain_name, query_type, query_class

def build_answer(domain_name, query_type, ttl, record_data):
    """
    Builds the DNS answer section.
    """
    record = struct.pack("!HHIH", 0xC00C, query_type, 1, ttl, len(record_data)) + record_data
    return record

def parse_answer(data):
    """
    Parses the DNS answer section from the raw data.
    """
    domain_name_offset = struct.unpack("!H", data[0:2])[0]  # Offset to domain name (CNAME/NAME)
    query_type, query_class, ttl, data_length = struct.unpack("!HHIH", data[2:10])
    record_data = data[10:10+data_length]
    return domain_name_offset, query_type, ttl, record_data

def build_error_response(query, rcode):
    """
    Builds a DNS error response with the specified RCODE.
    """
    # Get transaction ID from query and set flags for error
    transaction_id = struct.unpack("!H", query[:2])[0]
    flags = 0x8180 | rcode  # Standard response, with the specified error RCODE
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    header = build_header(transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
    question_section = query[12:]  # Copy the question section from the original query

    return header + question_section

def encode_record(record, record_type):
    """
    Encodes a DNS record (e.g., A, MX, PTR, NS).
    """
    if record_type == 1:  # A record (IPv4 address)
        ip_address = struct.unpack("!4B", bytes(map(int, record.split("."))))
        return struct.pack("!HHIH4B", 0xC00C, 1, 1, 3600, *ip_address)
    elif record_type == 2:  # NS record
        return struct.pack("!HHIH", 0xC00C, 2, 1, 3600, len(record), *record.encode())
    elif record_type == 15:  # MX record
        return struct.pack("!HHIH", 0xC00C, 15, 1, 3600, len(record), *record.encode())
    elif record_type == 12:  # PTR record
        return struct.pack("!HHIH", 0xC00C, 12, 1, 3600, len(record), *record.encode())
    return b""

def decode_record(data):
    """
    Decodes a DNS record from raw data.
    """
    # Extracts the domain name and record information from the raw data
    domain_name_offset = struct.unpack("!H", data[0:2])[0]  # Offset to domain name (CNAME/NAME)
    record_type, record_class, ttl, data_length = struct.unpack("!HHIH", data[2:10])
    record_data = data[10:10+data_length]
    return domain_name_offset, record_type, ttl, record_data

def rcode_to_string(rcode):
    """
    Converts an RCODE integer to a human-readable string.
    """
    return RCODES.get(rcode, "Unknown")

