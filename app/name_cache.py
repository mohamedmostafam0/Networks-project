import redis
import time
import pickle
from typing import Optional
import hashlib
import logging
from utils import parse_dns_response, parse_question_section

class Cache1:
    def __init__(self, redis_host="localhost", redis_port=6380, db=0):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
        print("Cache connection initialized")

    def get(self, cache_key: tuple) -> Optional[bytes]:
        """
        Retrieves the DNS query response from the cache if it exists and is still valid (TTL not expired).
        """
        # Serialize the cache key to a string
        key_string = self._serialize_cache_key(cache_key)
        cached_data = self.client.get(key_string)
        
        if cached_data:
            try:
                cached_response = pickle.loads(cached_data)
            except Exception as e:
                logging.error(f"Error deserializing cache data: {e}")
                return None
            if cached_response['ttl'] > time.time():
                return cached_response['response']
            else:
                # Cache entry expired, delete it
                self.client.delete(key_string)
                logging.info(f"Cache expired for key: {key_string}")
        return None

    def store(self, response: bytes):
        """
        Stores the DNS query response in the cache with a specified TTL.

        Parameters:
            response (bytes): The authoritative DNS response to store.
            ttl (int): Time-to-live in seconds for the cached entry.
        """
        ttl = 3600
        try:
            # Ensure TTL is an integer
            if not isinstance(ttl, int):
                raise ValueError(f"TTL must be an integer, got {type(ttl)}: {ttl}")

            # Extract the question section to build the cache key
            qname, qtype, qclass, _ = parse_question_section(response, 12)
            cache_key = (qname, qtype, qclass)

            # Serialize the cache key to a string
            key_string = self._serialize_cache_key(cache_key)

            # Create the cache entry
            cache_entry = {
                'response': response,  # Store the entire authoritative response
                'ttl': time.time() + ttl  # Set TTL based on current time
            }

            # Store in Redis
            self.client.setex(key_string, ttl, pickle.dumps(cache_entry))
            logging.info(f"Stored response in cache for key: {key_string}")
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
