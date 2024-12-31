import redis
from BaseCache import BaseCache

class NameCache(BaseCache):
    def __init__(self, redis_host="localhost", redis_port=6380, db=0):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
        print("Authoritative Cache connection initialized")

