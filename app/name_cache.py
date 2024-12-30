import redis
import time
import pickle
from typing import Optional
import hashlib
import logging
from utils import parse_dns_response, parse_question_section, parse_dns_query
from BaseCache import BaseCache

class NameCache(BaseCache):
    def __init__(self, redis_host="localhost", redis_port=6380, db=0):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
        print("Cache connection initialized")

