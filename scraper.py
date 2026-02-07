import hashlib
import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs
from bs4 import BeautifulSoup

uniquePages = 0
longestPage = 0
commonWords = {}
subdomains = {}

seen_content_hashes = set()
MIN_TOKENS = 50
MAX_BYTES = 5 * 1024 * 1024

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]
def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    if resp.status != 200 or not resp.raw_response or not resp.raw_response.content:
        return []

    headers = getattr(resp.raw_response, "headers", {}) or {}
    content_length = headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BYTES:
                return []
        except ValueError:
            pass

    content_bytes = resp.raw_response.content
    if len(content_bytes) > MAX_BYTES:
        return []

    urls = []
    content = BeautifulSoup(content_bytes, "html.parser")
    text = content.get_text(" ", strip=True)
    tokens = re.findall(r"[A-Za-z0-9]+", text)
    if len(tokens) < MIN_TOKENS:
        return []

    normalized = " ".join(tokens).lower()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if digest in seen_content_hashes:
        return []
    seen_content_hashes.add(digest)
    for link in content.find_all("a"):
        href = link.get("href")
        if not href:
            continue
        if href.startswith("mailto:") or href.startswith("javascript:"):
            continue
        abs_url = urljoin(resp.raw_response.url, href)
        abs_url, _frag = urldefrag(abs_url)
        urls.append(abs_url)
    return urls

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        host = parsed.hostname.lower() if parsed.hostname else ""
        allowed_domains = (
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu",
        )
        if not any(host == d or host.endswith("." + d) for d in allowed_domains):
            return False
        if len(url) > 200:
            return False
        if parsed.query:
            params = parse_qs(parsed.query)
            if len(params) > 5:
                return False
            for key, values in params.items():
                if len(key) > 50:
                    return False
                for val in values:
                    if len(val) > 100:
                        return False
            q = parsed.query.lower()
            if any(k in q for k in ["session", "sid", "phpsessid", "jsessionid"]):
                return False
        path_segments = [seg for seg in parsed.path.split("/") if seg]
        if len(path_segments) >= 4 and len(set(path_segments[-4:])) == 1:
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
