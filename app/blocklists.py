import requests
import yaml
import threading
from typing import List, Optional


class Block:
    """
    Represents a single blocked domain with its category and reason.
    """
    def __init__(self, domain: str, category: str, reason: str):
        self.domain = domain
        self.category = category
        self.reason = reason


class BlockList:
    """
    Represents a list of blocked domains and their details.
    """
    def __init__(self):
        self.blocks = []
        self.lock = threading.Lock()

    def add_block(self, block: Block):
        """
        Adds a block entry to the block list.
        """
        with self.lock:
            self.blocks.append(block)

    def query(self, domain: str) -> Optional[Block]:
        """
        Checks if a domain is present in the block list and returns the corresponding Block if found.
        """
        with self.lock:
            for block in self.blocks:
                if block.domain == domain:
                    return block
        return None

    def check(self, domain: str) -> bool:
        """
        Returns True if the domain is present in the block list, otherwise False.
        """
        return self.query(domain) is not None

    def load_from_urls(self, blocklist_urls: List[str]):
        """
        Downloads and parses blocklists from the given URLs concurrently.
        """
        threads = []

        for url in blocklist_urls:
            thread = threading.Thread(target=self._add_blocklist_from_url, args=(url,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        print(f"Block list compiled with {len(self.blocks)} entries.")

    def _add_blocklist_from_url(self, url: str):
        """
        Downloads and parses a blocklist from the given URL and adds its entries to the block list.
        """
        try:
            raw_yaml = self._download_blocklist(url)
            blocklist = self._parse_blocklist(raw_yaml)
            with self.lock:
                self.blocks.extend(blocklist)
            print(f"Block list downloaded and parsed from {url}")
        except Exception as e:
            print(f"Failed to download or parse block list from {url}: {e}")

    @staticmethod
    def _download_blocklist(url: str) -> bytes:
        """
        Downloads a block list from a given URL and returns its content as a byte array.
        """
        response = requests.get(url)
        response.raise_for_status()
        return response.content

    @staticmethod
    def _parse_blocklist(raw_yaml: bytes) -> List[Block]:
        """
        Parses raw YAML content into a list of Block objects.
        """
        blocklist_data = yaml.safe_load(raw_yaml)
        return [Block(**block) for block in blocklist_data]
