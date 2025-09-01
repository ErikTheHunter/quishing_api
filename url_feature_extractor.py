import re
import socket
import requests
import tldextract
from datetime import datetime
from urllib.parse import urlparse, unquote
from typing import Dict, Optional
from gibberish_detector import GibberishDetector


class URLFeatureExtractor:
    """
    Helper class to extract features from URL in a safe manner, the class extracts 
    both lexical and host-based heuristic 
    """

    # Suspicious characters 
    _SUSPICIOUS_CHARS = r"@|%|#|&|\$|\*|=|\+"

    def __init__(self,
                 virus_total_api_key: Optional[str] = None,
                 whoxy_api_key: Optional[str] = None,
                 openpagerank_api_key: Optional[str] = None,
                 request_timeout: int = 4,
                 gibberish_detector: Optional[GibberishDetector] = None):
        self.vt_key = virus_total_api_key
        self.whoxy_key = whoxy_api_key
        self.opr_key = openpagerank_api_key
        self.timeout = request_timeout

        self.gib_detector = gibberish_detector or GibberishDetector(download_dictionary=False)

    # my utility helpers 
    def extract(self, url: str) -> Dict[str, float]:
        """
        Extract features from the url and return as a dictionary.
        """
        # unshorten url if nescessary
        final_url, redirect_count = self._unshorten(url)

        lexical = self._lexical_features(final_url, original_url=url, redirect_count=redirect_count)
        host = self._host_features(final_url)
        # use python spread extractor to extract features
        features = {**lexical, **host}
        return features

    # Lexical features extracted from the URL string
    def _lexical_features(self, url: str, *, original_url: str, redirect_count: int) -> Dict[str, float]:
        """
        Helper function to extract only url lexical features.
        """
        parsed = urlparse(url)
        url_no_scheme = url.replace(parsed.scheme + '://', '') if parsed.scheme else url

        length = len(url)
        num_dots = url.count('.')
        num_hyphens = url.count('-')
        has_at_symbol = int('@' in url)
        host_only = parsed.netloc.split(':')[0]
        has_ip = int(self._domain_is_ip(host_only))
        port_specified = (':' in parsed.netloc)
        port_value = None
        if port_specified:
            try:
                port_value = int(parsed.netloc.split(':')[1])
            except Exception:
                # error adding port 
                port_value = None

        non_std_port = int(port_value not in (None, 80, 443))

        # Some Dangerous file extension that cannot be ignored (exe, js, zip, pdf, scr etc.)
        path = parsed.path.lower()
        dangerous_exts = {'.exe', '.js', '.zip', '.scr', '.pdf', '.bat', '.cmd', '.vbs'}
        dangerous_file_ext = int(any(path.endswith(ext) for ext in dangerous_exts))

        # Path depth (i.e number of segments)
        path_depth = float(len([seg for seg in path.split('/') if seg]))

        suspicious_char_count = len(re.findall(self._SUSPICIOUS_CHARS, url))

        # Word statistics (split on non-alphanumerics)
        tokens = re.split(r"[^A-Za-z0-9]", unquote(url_no_scheme))
        tokens = [t for t in tokens if t]
        avg_token_len = sum(map(len, tokens)) / len(tokens) if tokens else 0
        longest_token_len = max(map(len, tokens)) if tokens else 0

        # Additional lexical heuristics
        is_https = int(parsed.scheme == 'https')
        primary_domain = tldextract.extract(url).domain or ''
        primary_domain_len = len(primary_domain)
        num_query_params = url.count('=')
        protocol_in_domain = int('http' in parsed.netloc.lower())

        # Known shorteners can add more later based on research
        known_shorteners = {
            'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'lc.chat', 'soo.gd', 'l.ead.me',
            'q-r.to', 'one.link'
        }
        ext = tldextract.extract(original_url)
        is_shortened = int(f"{ext.domain}.{ext.suffix}" in known_shorteners or redirect_count > 0)

        idn_flag = int('xn--' in parsed.netloc)

        # Analyse URL for gibberish
        gibberish_count = 0
        for tok in tokens:
            if len(tok) <= 2:
                continue  # too short, no point analyzing for gibberish
            try:
                analysis = self.gib_detector.analyze_word(tok)
                if analysis['final_decision'].lower().startswith('gibberish'):
                    gibberish_count += 1
            except Exception:
                # Fail-safe: treat as non-gibberish if detector errors out
                pass

        gibberish_ratio = (gibberish_count / len(tokens)) if tokens else 0.0

        # prepare feature dictionary
        return {
            'url_length': float(length),
            'num_dots': float(num_dots),
            'num_hyphens': float(num_hyphens),
            'has_at_symbol': float(has_at_symbol),
            'has_ip_in_domain': float(has_ip),
            'suspicious_char_ratio': suspicious_char_count / length if length else 0,
            'suspicious_char_count': float(suspicious_char_count),
            'avg_token_length': float(avg_token_len),
            'longest_token_length': float(longest_token_len),
            'is_https': float(is_https),
            'primary_domain_length': float(primary_domain_len),
            'num_query_params': float(num_query_params),
            'protocol_in_domain': float(protocol_in_domain),
            'redirect_count': float(redirect_count),
            'is_shortened_url': float(is_shortened),
            'idn_homograph_flag': float(idn_flag),
            'non_standard_port': float(non_std_port),
            'dangerous_file_ext': float(dangerous_file_ext),
            'path_depth': path_depth,
            'gibberish_token_ratio': gibberish_ratio
        }

    # ------------------------------------------------------------------
    # Host-based features (WHOIS, DNS, reputation).
    # ------------------------------------------------------------------
    def _host_features(self, url: str) -> Dict[str, float]:
        features: Dict[str, float] = {
            'domain_age_days': None,
            'openpagerank': None,
            'virustotal_blacklisted': None,
            'dns_resolves': None,
            'domain_similarity_score': None,
            'subdomain_count': None,
            'tld_risk_score': None,

            # Extended WHOIS-derived signals -----------------------------
            'days_to_expiry': None,
            'registration_span_days': None,
            'days_since_last_update': None,
            'ns_count': None,
            'privacy_redacted': None,
            'registrar_badness': None,
        }

        ext = tldextract.extract(url)
        domain = ext.registered_domain
        if not domain:
            return features  # Failed to derive domain 

        features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0

        try:
            socket.gethostbyname(domain)
            features['dns_resolves'] = 1.0
        except Exception:
            features['dns_resolves'] = 0.0

        # if whoxy api key is provided, fetch whois data 
        if self.whoxy_key:
            try:
                resp = requests.get(
                    f"https://api.whoxy.com/?key={self.whoxy_key}&whois={domain}",
                    timeout=self.timeout,
                )
                data = resp.json()
                if data.get('status') == 1:
                    creation = data.get('create_date') or data.get('created_date')
                    expiry = data.get('expiry_date')
                    update = data.get('update_date')

                    # Parse date here using datetime library
                    def _parse(d):
                        try:
                            return datetime.strptime(d.split('T')[0], '%Y-%m-%d') if d else None
                        except Exception:
                            return None

                    creation_dt = _parse(creation)
                    expiry_dt = _parse(expiry)
                    update_dt = _parse(update)

                    # Domain age calculations
                    now = datetime.utcnow()
                    if creation_dt:
                        features['domain_age_days'] = (now - creation_dt).days
                    if expiry_dt:
                        features['days_to_expiry'] = (expiry_dt - now).days
                    if creation_dt and expiry_dt:
                        features['registration_span_days'] = (expiry_dt - creation_dt).days
                    if update_dt:
                        features['days_since_last_update'] = (now - update_dt).days

                    # Name server count
                    if isinstance(data.get('name_servers'), list):
                        features['ns_count'] = len(data['name_servers'])

                    email = (data.get('registrant_contact') or {}).get('email_address', '')
                    if email:
                        features['privacy_redacted'] = float(bool(re.search(r'privacy|protect', email, re.I)))

                    registrar_raw = data.get('registrar_name', '') or data.get('registrar', '')
                    low_cost_registrars = {"namecheap", "enom", "godaddy"}
                    features['registrar_badness'] = float(any(r in registrar_raw.lower() for r in low_cost_registrars))
            except Exception:
                pass  # leave as None

        # If open pagerank api key is provided, fetch OPR data
        if self.opr_key:
            try:
                resp = requests.get(
                    'https://openpagerank.com/api/v1.0/getPageRank',
                    params={'domains[]': domain},
                    headers={'API-OPR': self.opr_key},
                    timeout=self.timeout,
                )
                opr_json = resp.json()
                if opr_json and 'response' in opr_json and opr_json['response']:
                    features['openpagerank'] = opr_json['response'][0].get('page_rank_integer')
                    print("opr_json", opr_json['response'][0]['page_rank_integer'])
                
            except Exception as e:
                print("opr error", e)
                pass

        # if virus total api key is provided, fetch VT data
        if self.vt_key:
            try:
                headers = {'x-apikey': self.vt_key}
                vt_resp = requests.get(
                    f'https://www.virustotal.com/api/v3/domains/{domain}',
                    headers=headers,
                    timeout=self.timeout,
                )
                if vt_resp.status_code == 200:
                    vt_data = vt_resp.json()
                    malicious_votes = vt_data['data']['attributes']['last_analysis_stats']['malicious']
                    print("vt_data", malicious_votes)
                    features['virustotal_blacklisted'] = float(malicious_votes > 0)
            except Exception as e:
                print("vt error", e)
                pass

        try:
            from difflib import SequenceMatcher
            brand_list = [
                'paypal.com', 'google.com', 'apple.com', 'amazon.com',
                'facebook.com', 'microsoft.com', 'instagram.com', 'netflix.com'
            ]
            max_sim = 0.0
            for b in brand_list:
                ratio = SequenceMatcher(None, domain, b).ratio()
                max_sim = max(max_sim, ratio)
            features['domain_similarity_score'] = max_sim  # 0-1
        except Exception:
            pass

        # TLD risk (simple heuristic)
        high_risk_tlds = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click'}
        trusted_tlds = {'.gov', '.edu', '.mil'}
        tld = '.' + ext.suffix.lower()
        if tld in high_risk_tlds:
            features['tld_risk_score'] = 0.9
        elif tld in trusted_tlds:
            features['tld_risk_score'] = 0.1
        else:
            features['tld_risk_score'] = 0.5

        return features

    def _domain_is_ip(self, netloc: str) -> bool:
        try:
            socket.inet_aton(netloc)
            return True
        except socket.error:
            return False

    def _unshorten(self, url: str):
        try:
            # Ensure scheme to avoid requests exceptions
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            resp = requests.head(url, allow_redirects=True, timeout=self.timeout)
            final_url = resp.url if resp.ok else url
            redirect_count = len(resp.history)
            return final_url, redirect_count
        except Exception:
            return url, 0 