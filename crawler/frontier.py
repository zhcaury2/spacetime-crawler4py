import os
import shelve
import time

from threading import RLock, Condition
from urllib.parse import urlparse

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid

class Frontier(object):
    def __init__(self, config, restart):
        self.logger = get_logger("FRONTIER")
        self.config = config
        self.to_be_downloaded = list()
        self._lock = RLock()
        self._not_empty = Condition(self._lock)
        self._in_progress = 0
        self._last_access_by_domain = {}
        
        if not os.path.exists(self.config.save_file) and not restart:
            # Save file does not exist, but request to load save.
            self.logger.info(
                f"Did not find save file {self.config.save_file}, "
                f"starting from seed.")
        elif os.path.exists(self.config.save_file) and restart:
            # Save file does exists, but request to start from seed.
            self.logger.info(
                f"Found save file {self.config.save_file}, deleting it.")
            os.remove(self.config.save_file)
        if restart:
            for url in self.config.seed_urls:
                self.add_url(url)
        else:
            # Set the frontier state with contents of save file.
            total_count = self._parse_save_file()
            if total_count == 0:
                for url in self.config.seed_urls:
                    self.add_url(url)

    def _parse_save_file(self):
        ''' This function can be overridden for alternate saving techniques. '''
        with shelve.open(self.config.save_file) as save:
            total_count = len(save)
            values = list(save.values())
        tbd_count = 0
        with self._not_empty:
            for url, completed in values:
                if not completed and is_valid(url):
                    self.to_be_downloaded.append(url)
                    tbd_count += 1
        self.logger.info(
            f"Found {tbd_count} urls to be downloaded from {total_count} "
            f"total urls discovered.")
        return total_count

    def get_tbd_url(self):
        with self._not_empty:
            while not self.to_be_downloaded:
                if self._in_progress == 0:
                    return None
                self._not_empty.wait(timeout=0.1)
            self._in_progress += 1
            return self.to_be_downloaded.pop()

    def add_url(self, url):
        url = normalize(url)
        urlhash = get_urlhash(url)
        with self._not_empty:
            with shelve.open(self.config.save_file) as save:
                if urlhash in save:
                    return
                save[urlhash] = (url, False)
                save.sync()
            self.to_be_downloaded.append(url)
            self._not_empty.notify()
    
    def mark_url_complete(self, url):
        urlhash = get_urlhash(url)
        with self._not_empty:
            with shelve.open(self.config.save_file) as save:
                if urlhash not in save:
                    # This should not happen.
                    self.logger.error(
                        f"Completed url {url}, but have not seen it before.")
                save[urlhash] = (url, True)
                save.sync()
            self._in_progress = max(0, self._in_progress - 1)
            self._not_empty.notify_all()

    def wait_for_domain_politeness(self, url):
        domain = (urlparse(url).hostname or "").lower()
        if not domain:
            return
        while True:
            wait_time = 0.0
            with self._lock:
                now = time.time()
                last = self._last_access_by_domain.get(domain, 0.0)
                elapsed = now - last
                if elapsed >= self.config.time_delay:
                    self._last_access_by_domain[domain] = now
                    return
                wait_time = self.config.time_delay - elapsed
            time.sleep(wait_time)
