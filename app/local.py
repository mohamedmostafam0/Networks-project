import dns.message
import dns.rdatatype
import dns.rrset
import dns.resource

class Local:
    """
    Local groups DNS records by their type for easy management and parsing.
    """
    def __init__(self):
        self.standard = []

class StandardRecord:
    """
    Represents a DNS record with common fields.
    """
    def __init__(self, domain: str, record_type: str, value: str, ttl: int):
        self.domain = domain
        self.type = record_type
        self.value = value
        self.ttl = ttl

    def to_msg(self):
        """
        Converts the StandardRecord into a DNS message object (dns.message.Message).
        """
        try:
            # Create a DNS message
            msg = dns.message.Message()

            # Convert the type string to the corresponding DNS record type
            rtype = dns.rdatatype.from_text(self.type)

            # Set the question section of the message
            msg.question = [(self.domain + ".", rtype)]

            # Create the answer section
            rr = dns.rrset.RRset(self.domain + ".")
            rr.add(dns.resource.Record(self.type, self.value, self.ttl))

            # Append the answer to the message
            msg.answer.append(rr)

            return msg

        except Exception as e:
            raise ValueError(f"Error creating DNS message: {str(e)}")
