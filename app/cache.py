import redis
import time
import pickle
from typing import Optional

class Cache:
    def __init__(self, redis_host="localhost", redis_port=6379, db=0):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=True)

    def get(self, query: bytes) -> Optional[bytes]:
        """
        Retrieves the DNS query response from the cache if it exists and is still valid (TTL not expired).
        """
        query_key = self._generate_cache_key(query)
        cached_data = self.client.get(query_key)
        
        if cached_data:
            # Deserialize the cached response
            cached_response = pickle.loads(cached_data)
            if cached_response['ttl'] > time.time():
                return cached_response['response']
            else:
                # Cache entry expired, delete it
                self.client.delete(query_key)

        return None

    def store(self, query: bytes, response: bytes, ttl: int = 30000):
        """
        Stores the DNS query response in the cache with a specified TTL.
        """
        query_key = self._generate_cache_key(query)
        cache_entry = {
            'response': response,
            'ttl': time.time() + ttl
        }
        self.client.setex(query_key, ttl, pickle.dumps(cache_entry))

    def _generate_cache_key(self, query: bytes) -> str:
        """
        Generates a unique cache key for each DNS query.
        """
        return f"dns:{hash(query)}"
