import re
from urllib.parse import urlparse
from hashlib import sha256

seen_hashes = set()

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
    """ with open("temp", "w") as f:
        f.write((url))
        f.write("\n\n\n")
        f.write(type(resp.raw_response.content))
        f.write("\n\n")
    """
    # print(resp.raw_response.content)

    # Remove response with status code other than 200
    print("Extracting from: ", url, ", Status code: ", resp.status)

    if resp.status != 200:
        return []

    if resp is None or resp.raw_response is None:
        return []

    try:
        html_data = resp.raw_response.content.decode('utf-8', errors='ignore')
    except Exception:
        return []

    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html_data)).strip()

    if len(text) < 50 or re.search(r"(404|not\s*found|error|forbidden)", text, re.I):
        return []

    if len(text) / max(len(html_data), 1) < 0.1:
        return []

    content_hash = sha256(text.encode("utf-8")).hexdigest()
    if content_hash in seen_hashes:
        return []
    seen_hashes.add(content_hash)

    urls_before_process = []
    urls = []

    url_pattern = re.compile(
        r'''(?i)\b(?:href|src)\s*=\s*["']([^"']+)["']|((?:https?|ftp)://[^\s"'<>]+)'''
    )

    for match in url_pattern.findall(text):
        urls_before_process.append(match[0] or match[1])

    valid_domains = ("ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu")
    for link in urls_before_process:
        link = link.split('#')[0].strip().lower()
        parsed = urlparse(link)

        if re.search(r"([?&]page=\d+)|([?&]session)|([?&]sid=)|(\d{4}/\d{2}/\d{2})", link, re.I):
            continue
        if link.count("/") > 4:
            continue
        if not any(domain in parsed.netloc for domain in valid_domains):
            print(parsed.netloc)
            continue
        if any(pat in link for pat in ["/wp-json/", "/feed", "/oembed/", "/Classes/"]):
            continue

        urls.append(link)


    return list(urls)

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
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
