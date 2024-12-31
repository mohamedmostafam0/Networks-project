import redis
from BaseCache import BaseCache

class TLDCache(BaseCache):
    def __init__(self, redis_host="localhost", redis_port=6381, db=0):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
        print("TLD Cache connection initialized")

