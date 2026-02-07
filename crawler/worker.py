from threading import Thread, Lock
from urllib.parse import urlparse

from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time


class Worker(Thread):
    _politeness_lock = Lock()
    _last_access_by_domain = {}

    def __init__(self, worker_id, config, frontier):
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)

    def _wait_for_domain_politeness(self, url):
        domain = (urlparse(url).hostname or "").lower()
        if not domain:
            return
        while True:
            wait_time = 0.0
            with Worker._politeness_lock:
                now = time.time()
                last = Worker._last_access_by_domain.get(domain, 0.0)
                elapsed = now - last
                if elapsed >= self.config.time_delay:
                    Worker._last_access_by_domain[domain] = now
                    return
                wait_time = self.config.time_delay - elapsed
            time.sleep(wait_time)
        
    def run(self):
        while True:
            tbd_url = self.frontier.get_tbd_url()
            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                break
            self._wait_for_domain_politeness(tbd_url)
            resp = download(tbd_url, self.config, self.logger)
            self.logger.info(
                f"Downloaded {tbd_url}, status <{resp.status}>, "
                f"using cache {self.config.cache_server}.")
            scraped_urls = scraper.scraper(tbd_url, resp)
            for scraped_url in scraped_urls:
                self.frontier.add_url(scraped_url)
            self.frontier.mark_url_complete(tbd_url)
