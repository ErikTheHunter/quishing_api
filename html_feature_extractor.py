from __future__ import annotations
import re
from typing import Dict, Optional
import requests
from bs4 import BeautifulSoup

MAX_BYTES = 400_000  # Dont fetch pages more that 400KB
REQUEST_TIMEOUT = 4  # Timeout in seconds
# Mock user agent 
HEADERS = {"User-Agent": "ThreatAdaptiveHeuristicBot/1.0"}


class HTMLFeatureExtractor:
    """Helper class to extract content based features from HTML"""

    def __init__(self, timeout: int = REQUEST_TIMEOUT):
        self.timeout = timeout

    def extract(self, url: str) -> Dict[str, Optional[float]]:
        """
        Returns a dictionary of content based features
        """
        try:
            html = self._download_html(url)
            if html is None:
                return self._blank()
            return self._parse_features(html)
        except Exception:
            return self._blank()

    # Utility helpers 
    def _download_html(self, url: str) -> Optional[str]:
        resp = requests.get(
            url, 
            headers=HEADERS, 
            timeout=self.timeout, 
            allow_redirects=True, 
            stream=True
        )
        resp.raise_for_status()
        content = resp.raw.read(MAX_BYTES, decode_content=True)
        return content.decode(resp.apparent_encoding or 'utf-8', errors='replace')

    def _parse_features(self, html: str) -> Dict[str, Optional[float]]:
        soup = BeautifulSoup(html, 'html.parser')  # use beautiful soup to parse the HTML 

        # Count HTML tags 
        has_form = 1.0 if soup.find('form') else 0.0
        has_frame = 1.0 if soup.find(['frame', 'iframe']) else 0.0
        scripts = soup.find_all('script')
        has_script = 1.0 if scripts else 0.0
        num_anchors = float(len(soup.find_all('a')))
        num_buttons = float(len(soup.find_all('button')))
        num_img_tags = float(len(soup.find_all('img')))
        num_input_tags = float(len(soup.find_all('input')))
        num_links = float(len(soup.find_all('link')))
        num_script_tags = float(len(scripts))

        html_len = float(len(html))
        js_len = float(sum(len(s.get_text()) for s in scripts))

        # JS / HTML behavioural indicators
        has_redirect_js = 1.0 if re.search(r'window\.location|document\.location|meta http-equiv="refresh"', html, re.I) else 0.0
        onmouse_over = 1.0 if re.search(r'onmouseover\s*=', html, re.I) else 0.0
        pop_up_window = 1.0 if re.search(r'window\.open\s*\(', html, re.I) else 0.0

        # Favicon presence (link rel="icon" / rel="shortcut icon")
        favicon_present = 1.0 if soup.find('link', rel=re.compile(r'icon', re.I)) else 0.0

        # return dictionary of content based features
        return {
            'has_form_tag': has_form,
            'has_frame_tag': has_frame,
            'has_script_tag': has_script,
            'num_anchors': num_anchors,
            'num_buttons': num_buttons,
            'num_img_tags': num_img_tags,
            'num_input_tags': num_input_tags,
            'num_links': num_links,
            'num_script_tags': num_script_tags,
            'html_length': html_len,
            'js_length': js_len,
            'has_redirect_js': has_redirect_js,
            'onmouse_over': onmouse_over,
            'pop_up_window': pop_up_window,
            'favicon_present': favicon_present,
        }

    @staticmethod
    def _blank() -> Dict[str, Optional[float]]:
        """
        Default feature set in the event HTML cannot be parsed or fetched 
        """
        return {
            'has_form_tag': None,
            'has_frame_tag': None,
            'has_script_tag': None,
            'num_anchors': None,
            'num_buttons': None,
            'num_img_tags': None,
            'num_input_tags': None,
            'num_links': None,
            'num_script_tags': None,
            'html_length': None,
            'js_length': None,
            'has_redirect_js': None,
            'onmouse_over': None,
            'pop_up_window': None,
            'favicon_present': None,
        } 