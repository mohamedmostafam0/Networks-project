import redis
import time
import pickle
from typing import Optional
import hashlib
import logging
from utils import parse_question_section, parse_dns_query

class ResolverCache:
    def __init__(self, redis_host="localhost", redis_port=6379, db=0):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
        print("Cache connection initialized")

    def get(self, cache_key: tuple, transaction_id: int) -> Optional[bytes]:
        qname, qtype, qclass = cache_key
        qname = qname.lower().rstrip('.')  # Normalize domain name
        cache_key = (qname, qtype, qclass)  # Recreate normalized cache_key
        # logging.debug(f"qname is {qname}, qtype is {qtype}, qclass is {qclass}")
        # logging.debug(f"Trying to fetch cache for Key={cache_key} with transaction_id={transaction_id}")
        key_string = self._serialize_cache_key(cache_key)

        if not key_string:
            logging.error("Cache key serialization failed.")
            return None

        cached_data = self.client.get(key_string)
        # logging.debug(f"Trying to fetch cache for Key={key_string}, Cached Data={cached_data}")

        if not cached_data:
            logging.info(f"No cache entry found for Key={key_string}")
            return None

        try:
            cache_entry = pickle.loads(cached_data)
            # logging.debug(f"Deserialized Cache Entry: {cache_entry}")

            if cache_entry['ttl'] < time.time():
                # logging.info(f"Cache expired for Key={key_string}")
                self.client.delete(key_string)
                return None

            cached_response = cache_entry['response']
            cached_transaction_id, _, _, _ = parse_dns_query(cached_response)

            if cached_transaction_id != transaction_id:
                # logging.info("Transaction ID mismatch. Updating transaction ID in cached response.")
                response = bytearray(cached_response)
                response[0:2] = transaction_id.to_bytes(2, byteorder='big')
                return bytes(response)

            return cached_response
        except Exception as e:
            logging.error(f"Error processing cached data: {e}")
            return None


    def store(self, response: bytes):
        ttl = 3600
        logging.debug(f"storing in resolver cache")
        try:
            qname, qtype, qclass, _ = parse_question_section(response, 12)
            qname = qname.lower().rstrip('.')  # Normalize domain name
            cache_key = (qname, qtype, qclass)

            key_string = self._serialize_cache_key(cache_key)
            # logging.debug(f"Storing response in cache: Key={key_string}, TTL={ttl}")
            cache_entry = {
                'response': response,
                'ttl': time.time() + ttl
            }

            self.client.setex(key_string, ttl, pickle.dumps(cache_entry))
            logging.debug(f"Stored in cache: Key={key_string}, TTL={ttl}, Entry={cache_entry}")
        except Exception as e:
            logging.error(f"Error storing response in cache: {e}")


    def _serialize_cache_key(self, cache_key: tuple) -> str:
        """
        Serializes a tuple cache key into a string format suitable for Redis.

        Parameters:
            cache_key (tuple): The cache key as (domain_name, qtype, qclass).

        Returns:
            str: A serialized string suitable for Redis.
        """
        return f"dns:{hashlib.sha256(':'.join(map(str, cache_key)).encode()).hexdigest()}"
