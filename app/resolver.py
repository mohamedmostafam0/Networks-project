import struct
import logging
from cache import Cache
from udp_transport import UDPTransport
from authoritative import AuthoritativeServer
from root import RootServer
from tld import TLDServer 
from utils import (
    parse_dns_response,
    build_dns_header,
    build_dns_question,
    build_rr,
    parse_dns_query,
    validate_query,
    build_error_response,
    ip_to_bytes,
    bytes_to_ip,
    format_ns_name,
    extract_referred_ip
)


# Set up logging
logging.basicConfig(level=logging.DEBUG)

def resolve_query(query, cache: Cache, root_server: RootServer, tld_server: TLDServer, authoritative_server: AuthoritativeServer):
    """
    Resolves a DNS query by checking the cache and querying the Root, TLD, and Authoritative servers in sequence.
    """
    
    # Validate the query format
    try:
        transaction_id, domain_name, qtype, qclass = validate_query(query)
    except ValueError as e:
        logging.error(f"Invalid query: {e}")
        return build_error_response(query, rcode=1)  # Format error (RCODE 1)

    # Check the cache for the response
    cached_response = cache.get(query)
    if cached_response:
        logging.info(f"Cache hit for domain: {domain_name}")
        return cached_response

    logging.info(f"Cache miss for domain: {domain_name}. Querying root server.")

    # Query Root Server
    root_response = root_server.handle_root_query(query)
    if not root_response:
        logging.error(f"Root server could not resolve domain: {domain_name}")
        return build_error_response(query, rcode=3)  # NXDOMAIN

    # Query TLD Server
    tld_server_ip = extract_referred_ip(root_response)
    logging.debug(f"Referred TLD server IP: {tld_server_ip}")

    tld_response = tld_server.handle_tld_query(query)
    if not tld_response:
        logging.error(f"TLD server could not resolve domain: {domain_name}")
        return build_error_response(query, rcode=3)  # NXDOMAIN


    # Query Authoritative Server
    authoritative_server_ip = extract_referred_ip(tld_response)
    logging.debug(f"Referred authoritative server IP: {authoritative_server_ip}")
    authoritative_response = authoritative_server.handle_name_query(query)
    print("your name response is: ", authoritative_response)
    if not authoritative_response:
        logging.error(f"Authoritative server could not resolve domain: {domain_name}")
        return build_error_response(query, rcode=3)  # NXDOMAIN

    # Cache the successful response
    logging.info(f"Caching response for domain: {domain_name}")
    cache.store(query, authoritative_response)
    human_readable = parse_dns_response(authoritative_response)
    print("name server response is ", human_readable)
    return authoritative_response

def build_error_response(query, rcode):
    """
    Constructs an error response (e.g., NXDOMAIN) based on the query.
    """
    # Extract the transaction ID and question section from the query
    transaction_id = struct.unpack("!H", query[:2])[0]
    question = query[12:]  # Skip the header (12 bytes)

    # DNS header
    flags = 0x8180 | rcode  # Standard query response with error code
    qd_count = 1  # One question
    an_count = 0  # No answer records
    ns_count = 0  # No authority records
    ar_count = 0  # No additional records
    header = build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)

    return header + question  # Return the header and question section

