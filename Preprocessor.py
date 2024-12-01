import re
import socket
import whois
import idna
from urllib.parse import urlparse
from datetime import datetime

# functions for specific feature extraction
def is_ip(url):
    try:
        socket.inet_aton(url)
        return True
    except socket.error:
        return False

def extract_domain_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception:
        return None


#  Total length of URL
# def length_url(url):
#     return 1.0;

#  Length of hostname
def length_hostname(url):
    parsed_url = urlparse(url)
    return len(parsed_url.hostname) / len(url) if parsed_url.hostname else 0

#  IP address check
def ip(url):
    parsed_url = urlparse(url) 
    return int(is_ip(parsed_url.hostname));

#  Number of dots
def nb_dots(url):
    return url.count('.') / len(url)

#  Number of hyphens
def nb_hyphens(url):
    return url.count('-') / len(url)

#  Number of '@' symbols
def nb_at(url):
    return url.count('@') / len(url)

#  Number of '?' symbols
def nb_qm(url):
    return url.count('?') / len(url)

#  Number of '&' symbols
def nb_and(url):
    return url.count('&') / len(url)

#  Number of '|' symbols
def nb_or(url):
    return url.count('|') / len(url)

#  Number of '=' symbols
def nb_eq(url):
    return url.count('=') / len(url)

#  Number of underscores
def nb_underscore(url):
    return url.count('_') / len(url)

#  Number of '~' symbols
def nb_tilde(url):
    return url.count('~') / len(url)

#  Number of '%' symbols
def nb_percent(url):
    return url.count('%') / len(url)

#  Number of slashes
def nb_slash(url):
    return url.count('/') / len(url)

#  Number of '*' symbols
def nb_star(url):
    return url.count('*') / len(url)

#  Number of colons ':'
def nb_colon(url):
    return url.count(':') / len(url)

#  Number of commas
def nb_comma(url):
    return url.count(',') / len(url)

#  Number of semicolons
def nb_semicolumn(url):
    return url.count(';') / len(url)

#  Number of dollar signs
def nb_dollar(url):
    return url.count('$') / len(url)

#  Number of spaces
def nb_space(url):
    return url.count(' ') / len(url)

#  Occurrences of 'www'
def nb_www(url):
    return url.count('www') / len(url)

#  Occurrences of 'com'
def nb_com(url):
    return url.count('com') / len(url)

#  Number of '//' in the URL
def nb_dslash(url):
    return url.count('//') / len(url)

#  Presence of 'http' in the path
def http_in_path(url):
    parsed_url = urlparse(url)
    return float(parsed_url.scheme == "http");

#  Presence of 'https' in subdomain or path
def https_token(url):
    parsed_url = urlparse(url)
    return float(parsed_url.scheme == "https");

#  Ratio of digits in the URL
def ratio_digits_url(url):
    return sum(c.isdigit() for c in url) / len(url)

#  Ratio of digits in the hostname
def ratio_digits_host(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ''
    return sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0

#  Punycode presence
def punycode(url):
    parsed_url = urlparse(url)
    if parsed_url.hostname is None:
        return 0.0
    try:
        labels = parsed_url.hostname.split('.')
        punycode_labels = []
        for label in labels:
            if len(label) >= 1:
                punycode_labels.append(idna.alabel(label).decode("ascii"));

        # if any label starts with 'xn--', which indicates a Punycode encoding
        puny_count = sum([1 for label in punycode_labels if label.startswith("xn--")])
        return 1.0 if puny_count > 0 else 0.0

    except idna.core.InvalidCodepoint as e:
        return 0.0

#  Port presence
def port(url):
    parsed_url = urlparse(url)
    return float(parsed_url.port is not None)

#  TLD in path
def tld_in_path(url):
    parsed_url = urlparse(url)
    return parsed_url.path.count(parsed_url.hostname.split('.')[-1]) if parsed_url.hostname else 0

#  TLD in subdomain
def tld_in_subdomain(url):
    parsed_url = urlparse(url)
    subdomain = parsed_url.hostname.split('.')[:-2] if parsed_url.hostname else []
    return float(any(parsed_url.hostname.split('.')[-1] in sub for sub in subdomain))

#  Abnormal subdomain structure
def abnormal_subdomain(url):
    parsed_url = urlparse(url)
    subdomains = parsed_url.hostname.split('.')[:-2] if parsed_url.hostname else []
    return float(len(subdomains) > 2)

#  Number of subdomains if greater than one
def nb_subdomains(url):
    parsed_url = urlparse(url)
    return float(len(parsed_url.hostname.split('.')) - 2 > 1) if parsed_url.hostname else 0

#  Prefix/suffix in domain name
def prefix_suffix(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname.split('.')[0] if parsed_url.hostname else ''
    return float('-' in domain)

#  Random domain
def random_domain(url):
    domain = urlparse(url).hostname.split('.')[0] if urlparse(url).hostname else ''
    return float(len(domain) > 10 and sum(c.isalpha() for c in domain) < len(domain) * 0.5)

#  URL shortening service
def shortening_service(url):
    shortening_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'bit.do']
    return float(any(sd in url for sd in shortening_domains))



def length_words_raw(url):
    words = re.findall(r'\b\w+\b', url)
    return sum(len(word) for word in words) / len(url)

#  Repeated characters in URL
def char_repeat(url):
    return max([url.count(c) for c in set(url)]) / len(url)

#  Shortest word in raw URL
def shortest_words_raw(url):
    words = re.findall(r'\b\w+\b', url)
    return (len(min(words, key=len)) / len(url)) if words else 0

#  Shortest word in hostname
def shortest_word_host(url):
    parsed_url = urlparse(url)
    words = parsed_url.hostname.split('.') if parsed_url.hostname else []
    return (len(min(words, key=len)) / len(url)) if words else 0

#  Shortest word in path
def shortest_word_path(url):
    parsed_url = urlparse(url)
    words = parsed_url.path.split('/') if parsed_url.path else []
    return (len(min(words, key=len)) / len(url)) if words else 0

#  Longest word in raw URL
def longest_words_raw(url):
    words = re.findall(r'\b\w+\b', url)
    return (len(max(words, key=len)) / len(url)) if words else 0

#  Longest word in hostname
def longest_word_host(url):
    parsed_url = urlparse(url)
    words = parsed_url.hostname.split('.') if parsed_url.hostname else []
    return (len(max(words, key=len)) / len(url)) if words else 0

#  Longest word in path
def longest_word_path(url):
    parsed_url = urlparse(url)
    words = parsed_url.path.split('/') if parsed_url.path else []
    return (len(max(words, key=len)) / len(url)) if words else 0

#  Average word length in raw URL
def avg_words_raw(url):
    words = re.findall(r'\b\w+\b', url)
    return (sum(len(word) for word in words) / len(words)) / len(url) if words else 0

#  Average word length in hostname
def avg_word_host(url):
    parsed_url = urlparse(url)
    words = parsed_url.hostname.split('.') if parsed_url.hostname else []
    return (sum(len(word) for word in words) / len(words)) / len(url) if words else 0

#  Average word length in path
def avg_word_path(url):
    parsed_url = urlparse(url)
    words = parsed_url.path.split('/') if parsed_url.path else []
    return (sum(len(word) for word in words) / len(words)) / len(url) if words else 0

#  Phishing hints in URL
def phish_hints(url):
    phishing_indicators = ['login', 'secure', 'account', 'update', 'verification']
    return float(any(hint in url.lower() for hint in phishing_indicators))

#  Path extension 
def path_extension(url):
    # Regular expression to match file extensions, e.g., .jpg, .pdf, .html
    pattern = r'\.\w{2,4}(/|$)';
    return int(bool(re.search(pattern, url)));

# suspecious_tld ..
def suspecious_tld(url):
    suspicious_tlds_list = {
        ".zip", ".xyz", ".top", ".work", ".click", ".info", ".biz", ".win", ".cn",
        ".ru", ".cc", ".pw", ".party", ".tk", ".ml", ".ga", ".cf", ".gq"
    }
    try:
        parsed_url = urlparse(url)
        # Extract the TLD from the hostname
        tld = "." + parsed_url.hostname.split('.')[-1]
        # Check if the TLD is in the list of suspicious TLDs
        return int(tld in suspicious_tlds_list)
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return 0;
    pass;


def extract_all_features(url):
    features = [
        length_hostname(url),
        ip(url),
        nb_dots(url),
        nb_hyphens(url),
        nb_at(url),
        nb_qm(url),
        nb_and(url),
        nb_or(url),
        nb_eq(url),
        nb_underscore(url),
        nb_tilde(url),
        nb_percent(url),
        nb_slash(url),
        nb_star(url),
        nb_colon(url),
        nb_comma(url),
        nb_semicolumn(url),
        nb_dollar(url),
        nb_space(url),
        nb_www(url),
        nb_com(url),
        nb_dslash(url),
        http_in_path(url),
        https_token(url),
        ratio_digits_url(url),
        ratio_digits_host(url),
        punycode(url),
        port(url),
        tld_in_path(url),
        tld_in_subdomain(url),
        abnormal_subdomain(url),
        nb_subdomains(url),
        prefix_suffix(url),
        random_domain(url),
        shortening_service(url),
        length_words_raw(url),
        char_repeat(url),
        shortest_words_raw(url),
        shortest_word_host(url),
        shortest_word_path(url),
        longest_words_raw(url),
        longest_word_host(url),
        longest_word_path(url),
        avg_words_raw(url),
        avg_word_host(url),
        avg_word_path(url),
        phish_hints(url),
        path_extension(url),
        suspecious_tld(url),
    ]
    return features;