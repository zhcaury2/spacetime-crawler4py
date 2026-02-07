import hashlib
import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qsl
from bs4 import BeautifulSoup

uniquePages = 0
longestPage = 0
commonWords = {}
subdomains = {}

seen_content_hashes = set()
MIN_TOKENS = 50
MIN_UNIQUE_TOKEN_RATIO = 0.12
MAX_BYTES = 5 * 1024 * 1024
MAX_QUERY_PARAMS = 4
MAX_QUERY_KEY_LEN = 40
MAX_QUERY_VALUE_LEN = 80
MAX_LINKS_PER_PAGE = 500
SHINGLE_SIZE = 4
SIMHASH_BITS = 64
SIMHASH_BANDS = 8
SIMHASH_BAND_WIDTH = SIMHASH_BITS // SIMHASH_BANDS
SIMHASH_MAX_DISTANCE = 8
SIMHASH_FALLBACK_RECENT = 512
SIMHASH_MAX_STORED = 5000
ALLOWED_DOMAIN_SUFFIXES = (
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
)
DOKUWIKI_TRAP_KEYS = {
    "do",
    "idx",
    "tab_files",
    "tab_details",
    "image",
    "media",
    "ns",
}
TRACKING_QUERY_KEYS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
}
BLOCKED_HOST_PATH_PREFIXES = {
    "archive.ics.uci.edu": ("/ml", "/machine-learning-databases"),
}
CALENDAR_PATH_HINTS = (
    "/calendar",
    "/calendars",
    "/events",
    "/event",
)
CALENDAR_QUERY_KEYS = {
    "ical",
    "outlook-ical",
    "tribe-bar-date",
    "eventdisplay",
    "eventdate",
    "event_id",
    "date",
    "month",
    "year",
    "week",
    "day",
}
simhash_buckets = {}
recent_simhash_signatures = []


def _exact_content_signature(tokens):
    # Exact similarity fingerprint over normalized token stream.
    normalized = " ".join(tok.lower() for tok in tokens)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _hash64(text):
    return int.from_bytes(
        hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest(),
        byteorder="big",
        signed=False,
    )


def _token_shingles(tokens, shingle_size=SHINGLE_SIZE):
    if len(tokens) < shingle_size:
        return []
    shingles = []
    for i in range(len(tokens) - shingle_size + 1):
        shingles.append(_hash64(" ".join(tokens[i:i + shingle_size])))
    return shingles


def _simhash(feature_hashes):
    if not feature_hashes:
        return 0
    vector = [0] * SIMHASH_BITS
    for h in feature_hashes:
        for bit in range(SIMHASH_BITS):
            if (h >> bit) & 1:
                vector[bit] += 1
            else:
                vector[bit] -= 1
    signature = 0
    for bit in range(SIMHASH_BITS):
        if vector[bit] >= 0:
            signature |= (1 << bit)
    return signature


def _hamming_distance(a, b):
    return (a ^ b).bit_count()


def _simhash_bucket_keys(signature):
    mask = (1 << SIMHASH_BAND_WIDTH) - 1
    for band in range(SIMHASH_BANDS):
        yield band, (signature >> (band * SIMHASH_BAND_WIDTH)) & mask


def _is_near_duplicate(signature):
    candidates = set()
    for key in _simhash_bucket_keys(signature):
        if key in simhash_buckets:
            candidates.update(simhash_buckets[key])
    # LSH banding can miss true near matches; compare against a bounded
    # recent window to improve recall without scanning all history.
    if not candidates:
        candidates.update(recent_simhash_signatures[-SIMHASH_FALLBACK_RECENT:])
    for candidate in candidates:
        if _hamming_distance(signature, candidate) <= SIMHASH_MAX_DISTANCE:
            return True
    return False


def _store_signature(signature):
    for key in _simhash_bucket_keys(signature):
        if key not in simhash_buckets:
            simhash_buckets[key] = set()
        simhash_buckets[key].add(signature)
    recent_simhash_signatures.append(signature)
    if len(recent_simhash_signatures) > SIMHASH_MAX_STORED:
        del recent_simhash_signatures[:len(recent_simhash_signatures) - SIMHASH_MAX_STORED]


def _is_query_trap(parsed):
    if not parsed.query:
        return False
    query_lower = parsed.query.lower()
    if any(k in query_lower for k in ["session", "sid", "phpsessid", "jsessionid"]):
        return True

    params = parse_qsl(parsed.query, keep_blank_values=True)
    if len(params) > MAX_QUERY_PARAMS:
        return True

    for key, value in params:
        key = key.lower()
        value = value.lower()
        if len(key) > MAX_QUERY_KEY_LEN or len(value) > MAX_QUERY_VALUE_LEN:
            return True
        if key in TRACKING_QUERY_KEYS:
            return True
        if key in {"replytocom", "sort", "filter", "order", "share", "ical"}:
            return True
        if key == "do" and value in {
            "",
            "login",
            "edit",
            "index",
            "recent",
            "revisions",
            "backlink",
            "media",
            "export_code",
        }:
            return True

    # DokuWiki query combinations produce large low-value URL families.
    path = parsed.path.lower()
    if "doku.php" in path and any(k.lower() in DOKUWIKI_TRAP_KEYS for k, _ in params):
        return True

    return False


def _is_blocked_ml_dataset_url(host, path):
    prefixes = BLOCKED_HOST_PATH_PREFIXES.get(host, ())
    return any(path.startswith(prefix) for prefix in prefixes)


def _is_calendar_trap(parsed):
    path = (parsed.path or "/").lower()
    # Date-like terminal paths are often infinite calendar navigations.
    if re.search(r"/\d{4}[-/]\d{2}[-/]\d{2}/?$", path):
        return True
    if re.search(r"/\d{4}/\d{2}/\d{2}/?$", path):
        return True
    if re.search(r"/events?/(week|day|month)/?$", path):
        return True
    if re.search(r"(events?[-_/]?week|events?[-_/]?month|events?[-_/]?day)/?$", path):
        return True

    if any(hint in path for hint in CALENDAR_PATH_HINTS):
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if any(k.lower() in CALENDAR_QUERY_KEYS for k, _ in params):
            return True

    return False

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
    seen_urls = set()
    content = BeautifulSoup(content_bytes, "html.parser")
    text = content.get_text(" ", strip=True)
    tokens = re.findall(r"[A-Za-z0-9]+", text)
    if len(tokens) < MIN_TOKENS:
        return []
    unique_ratio = len(set(tokens)) / float(len(tokens))
    if unique_ratio < MIN_UNIQUE_TOKEN_RATIO:
        return []

    digest = _exact_content_signature(tokens)
    if digest in seen_content_hashes:
        return []
    normalized_tokens = [tok.lower() for tok in tokens]
    shingle_hashes = _token_shingles(normalized_tokens)
    if not shingle_hashes:
        shingle_hashes = [_hash64(tok) for tok in set(normalized_tokens)]
    simhash_signature = _simhash(shingle_hashes)
    if _is_near_duplicate(simhash_signature):
        return []
    seen_content_hashes.add(digest)
    _store_signature(simhash_signature)
    links = content.find_all("a")
    if len(links) > MAX_LINKS_PER_PAGE:
        return []
    for link in links:
        href = link.get("href")
        if not href:
            continue
        if href.startswith("mailto:") or href.startswith("javascript:"):
            continue
        abs_url = urljoin(resp.raw_response.url, href)
        abs_url, _frag = urldefrag(abs_url)
        if abs_url in seen_urls:
            continue
        seen_urls.add(abs_url)
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
        host = parsed.hostname.lower().strip(".") if parsed.hostname else ""
        path = parsed.path or "/"
        # Assignment scope: *.ics.uci.edu/*, *.cs.uci.edu/*,
        # *.informatics.uci.edu/*, *.stat.uci.edu/*
        if not any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAIN_SUFFIXES):
            return False
        if not path.startswith("/"):
            return False
        # Assignment warning: do not crawl UCI ML repository/datasets.
        if _is_blocked_ml_dataset_url(host, path.lower()):
            return False
        # Assignment warning: avoid calendar/event-week traps.
        if _is_calendar_trap(parsed):
            return False
        if len(url) > 200:
            return False
        if _is_query_trap(parsed):
            return False
        if any(k in path for k in ["/login", "/logout", "/signin", "/signup"]):
            return False
        path_segments = [seg for seg in parsed.path.split("/") if seg]
        if len(path_segments) >= 4 and len(set(path_segments[-4:])) == 1:
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|svg|webp|tiff?|mid|mp2|mp3|mp4|webm"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv|ttf|otf|eot|woff2?"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
