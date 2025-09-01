from __future__ import annotations

import math
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from url_feature_extractor import URLFeatureExtractor
from html_feature_extractor import HTMLFeatureExtractor


class ThreatAdaptiveHeuristicDetector:
    """
    Heuristic detector class to detect phishing URLs.
    """

    DEFAULT_THRESHOLDS = {
        'genuine_max': 40,   # 0-40 ⇒ genuine
        'suspicious_max': 60  # 31-60 ⇒ suspicious; >60 ⇒ malicious
    }

    _NEUTRAL_DEFAULT = 0.5  # used when a numeric feature is missing

    # initialize the class with nescessary dependencies and keys to third party services
    def __init__(self,
                 feature_weights_path: str = 'config/feature_weights.yaml',
                 threat_intel_path: str = 'config/threat_intelligence.yaml',
                 vt_key: Optional[str] = None,
                 whoxy_key: Optional[str] = None,
                 opr_key: Optional[str] = None,
                 enable_content: bool = True,
                 aggregation: str = 'average'):
        # load feature weights
        self.config_weights = self._load_feature_weights(feature_weights_path)
        self.feature_weights = self.config_weights.get('feature_weights', {})
        self.thresholds = self.config_weights.get('thresholds', self.DEFAULT_THRESHOLDS)
        self.dynamic_modifiers: Dict[str, float] = {}
        self._threat_intel_path = threat_intel_path
        self._load_threat_intel(threat_intel_path)

        # Leverage the existing URL feature extractor class to extract features
        self.extractor = URLFeatureExtractor(
            virus_total_api_key=vt_key,
            whoxy_api_key=whoxy_key,
            openpagerank_api_key=opr_key,
        )

        self.enable_content = enable_content
        # initialize the HTML feature extractor class to extract content based features 
        self.html_extractor = HTMLFeatureExtractor() if enable_content else None

        assert aggregation in {'average', 'additive'}, "aggregation must be 'average' or 'additive'"
        self.aggregation = aggregation

    def analyse(self, url: str) -> Dict[str, object]:
        """
        Analyse the given URL and return dictionary object containing the results 
        """
        features = self.extractor.extract(url)

        if self.enable_content and self.html_extractor:
            content_feats = self.html_extractor.extract(url)
            features.update(content_feats)

        total_score, breakdown = self._score(features)
        qualitative = self._categorise(total_score)

        # response
        response = {
            'url': url,
            'analysed_at': datetime.utcnow().isoformat() + 'Z',
            'phish_score': round(total_score, 2),
            'category': qualitative,
            'feature_breakdown': {k: v for k, v in breakdown.items() if k != '__reasons__'},
        }

        # If the url is not genuine, provide reasons why the url was marked as malicious
        if qualitative != 'genuine':
            response['reasons'] = breakdown.get('__reasons__', [])

        return response

    def update_feature_priorities(self, signals: Dict[str, float]):
        
        for feat, mult in signals.items():
            if feat in self.feature_weights:
                self.dynamic_modifiers[feat] = self.dynamic_modifiers.get(feat, 1.0) * mult

    # My utility helpers 
    def _score(self, features: Dict[str, Optional[float]]):
        breakdown: Dict[str, float] = {}
        
        total_risk = 0.0  # positive contributions
        total_trust = 0.0  # absolute of negative contributions
        denom = 0.0  # cumulative weight (for average mode)
        reasons: List[str] = []

        for feat_name, base_weight in self.feature_weights.items():
            value = features.get(feat_name)

            # if a feature is not present, or could not be derived, skip
            if value is None:
                continue

            weight = base_weight * self.dynamic_modifiers.get(feat_name, 1.0)

            # Normalise or map raw feature to 0-1 risk factor
            risk_factor = self._risk_transform(feat_name, value)

            # collect reasons when risk very high
            if risk_factor >= 0.8:
                reason = self._reason_for(feat_name, value)
                if reason:
                    reasons.append(reason)

            contribution = risk_factor * weight
            breakdown[feat_name] = round(contribution * 100, 2)

            if contribution >= 0:
                total_risk += contribution
            else:
                total_trust += abs(contribution)

            denom += weight  # for average mode or total weight cap in additive

        # Scale to 0-100
        if self.aggregation == 'average':
            # apply this logic if average 
            net = total_risk - 0.6 * total_trust
            total_scaled = (net / denom) * 100 if denom else 0
        else:  # additive
            # apply this logic if we are using the additive approach
            net = total_risk - 0.6 * total_trust
            total_scaled = net * 100
            
            

        # Cap the score to 100
        total_scaled = max(min(total_scaled, 100), 0)
        breakdown['__reasons__'] = reasons  # internal key
        return total_scaled, breakdown

    def _categorise(self, score: float) -> str:
        # categorise a url as malicious, suspicious or genuine based on the score
        if score <= self.thresholds['genuine_max']:
            return 'genuine'
        if score <= self.thresholds['suspicious_max']:
            return 'suspicious'
        return 'malicious'

    # helper function to generate risk score from the feature
    def _risk_transform(self, feat: str, value: Optional[float]) -> float:
        """
        Transform the feature into a risk value of 0 - 1 range
        """
        if value is None:
            return self._NEUTRAL_DEFAULT

        if feat == 'url_length':
            return min(value / 100.0, 1.0)  # long URL ⇒ higher risk
        if feat == 'num_dots':
            return min(value / 6.0, 1.0)
        if feat == 'num_hyphens':
            return min(value / 10.0, 1.0)
        if feat == 'has_at_symbol' or feat == 'has_ip_in_domain':
            return float(value)
        if feat == 'suspicious_char_ratio':
            return min(value * 10, 1.0)
        if feat == 'suspicious_char_count':
            return min(value / 10.0, 1.0)
        if feat == 'avg_token_length':
            return 1 - math.exp(-value / 10)
        if feat == 'longest_token_length':
            return min(value / 30.0, 1.0)

        if feat == 'gibberish_token_ratio':
            # Directly map the 0-1 ratio to equivalent risk.
            return float(value)

        if feat == 'domain_age_days':
            if value is None:
                return self._NEUTRAL_DEFAULT
            return 1.0 if value < 30 else (0.3 if value < 365 else 0.05)
        if feat == 'openpagerank':
            # Map OpenPageRank (0–10) to a *trust-aware* risk score in the range −1 … +1.
            # High-reputation domains (rank ≥8) actively *subtract* risk whereas
            # very low-reputation ones increase it.  Rank 5 is treated as neutral.
            if value is None:
                return self._NEUTRAL_DEFAULT

            try:
                rank_val = float(value)
            except Exception:
                rank_val = 0.0

            rank_val = max(0.0, min(rank_val, 10.0))  # clamp to expected bounds
            # Centre around 5 and scale so that 10 → −1  and 0 → +1
            return (5.0 - rank_val) / 5.0
        if feat == 'virustotal_blacklisted':
            return float(value)
        if feat == 'dns_resolves':
            return 1 - float(value)  # resolves => low risk, fail => high risk
        if feat == 'domain_similarity_score':
            # Only penalise when similarity to a well-known brand is significant.
            sim = float(value)
            if sim >= 0.8:
                return 1.0  # very close imitation ⇒ maximal risk
            if sim >= 0.6:
                return 0.7  # moderate similarity ⇒ medium risk
            return 0.0  # low similarity ⇒ no added risk
        if feat == 'subdomain_count':
            return min(value / 4.0, 1.0)
        if feat == 'tld_risk_score':
            return float(value)
        if feat == 'is_https':
            return 0.2 if value else 1.0
        if feat == 'primary_domain_length':
            return min(value / 25.0, 1.0)
        if feat == 'num_query_params':
            return min(value / 5.0, 1.0)
        if feat == 'protocol_in_domain':
            return float(value)
        if feat == 'redirect_count':
            return min(value / 2.0, 1.0)
        if feat == 'is_shortened_url':
            return float(value)
        if feat == 'idn_homograph_flag':
            return float(value)
        if feat == 'non_standard_port':
            return float(value)
        

        if feat in {'has_form_tag', 'has_frame_tag', 'has_script_tag',
                    'has_redirect_js', 'onmouse_over', 'pop_up_window'}:
            return float(value)
        if feat == 'favicon_present':
            return 0.2 if value else 0.8
        if feat in {'num_anchors', 'num_buttons', 'num_img_tags', 'num_input_tags',
                    'num_links', 'num_script_tags'}:
            return min(value / 100.0, 1.0)
        if feat == 'html_length':
            # very small (<2k) or very large (>200k) suspicious
            if value < 2000 or value > 200000:
                return 1.0
            return 0.1
        if feat == 'js_length':
            return min(value / 50000.0, 1.0)

        # WHOIS features
        if feat == 'days_to_expiry':
            if value is None:
                return self._NEUTRAL_DEFAULT
            if value < 30:
                return 1.0
            if value < 365:
                return 0.6
            return 0.1
        if feat == 'registration_span_days':
            if value is None:
                return self._NEUTRAL_DEFAULT
            return 1.0 if value < 365 else 0.1
        if feat == 'days_since_last_update':
            if value is None:
                return self._NEUTRAL_DEFAULT
            return 0.8 if value < 7 else 0.2

        # Lexical dangerous file extension (binary)
        if feat == 'dangerous_file_ext':
            return float(value)

        # Fallback
        return self._NEUTRAL_DEFAULT

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------
    def _load_feature_weights(self, path: str):
        default_cfg = {
            'feature_weights': {
                'url_length': 0.1,
                'num_dots': 0.07,
                'num_hyphens': 0.05,
                'has_at_symbol': 0.05,
                'has_ip_in_domain': 0.18,
                'suspicious_char_ratio': 0.08,
                'suspicious_char_count': 0.05,
                'avg_token_length': 0.05,
                'longest_token_length': 0.05,
                'domain_age_days': 0.12,
                'openpagerank': 0.25,
                'virustotal_blacklisted': 0.35,
                'dns_resolves': 0.05,
                'domain_similarity_score': 0.05,
                'subdomain_count': 0.1,
                'tld_risk_score': 0.05,
                'is_https': 0.05,
                'primary_domain_length': 0.05,
                'num_query_params': 0.03,
                'protocol_in_domain': 0.04,
                'redirect_count': 0.03,
                'is_shortened_url': 0.03,
                'idn_homograph_flag': 0.05,
                'has_form_tag': 0.02,
                'has_frame_tag': 0.03,
                'has_script_tag': 0.03,
                'num_anchors': 0.03,
                'num_buttons': 0.02,
                'num_img_tags': 0.02,
                'num_input_tags': 0.03,
                'num_links': 0.03,
                'num_script_tags': 0.03,
                'html_length': 0.04,
                'js_length': 0.04,
                'has_redirect_js': 0.05,
                'onmouse_over': 0.04,
                'pop_up_window': 0.05,
                'favicon_present': 0.02,
                'days_to_expiry': 0.05,
                'registration_span_days': 0.04,
                'days_since_last_update': 0.03,
                'non_standard_port': 0.1,
                'dangerous_file_ext': 0.20,
                'path_depth': 0.05,
                'gibberish_token_ratio': 0.25,
            },
            'thresholds': self.DEFAULT_THRESHOLDS,
        }

        if Path(path).exists():
            try:
                with open(path, 'r') as fh:
                    user_cfg = yaml.safe_load(fh) or {}
                    # Merge feature weights (user overrides defaults)
                    default_cfg['feature_weights'].update(user_cfg.get('feature_weights', {}))
                    # Merge thresholds if provided
                    if 'thresholds' in user_cfg:
                        if isinstance(user_cfg['thresholds'], dict):
                            default_cfg['thresholds'].update(user_cfg['thresholds'])
            except Exception:
                pass

        return default_cfg

    def _load_threat_intel(self, path: str):
        """Placeholder for future threat-intel driven dynamic adjustment."""
        if not Path(path).exists():
            return
        try:
            with open(path, 'r') as fh:
                intel = yaml.safe_load(fh)
            # Example: if a new TLD is trending we could boost *url_length* weight
            trending_tlds = intel.get('tld_intelligence', {}).get('high_risk_categories', {})
            if trending_tlds:
                # simplistic example: emphasise lexical metrics
                self.update_feature_priorities({'num_dots': 1.2, 'suspicious_char_ratio': 1.2})
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Human-readable reasons
    # ------------------------------------------------------------------
    def _reason_for(self, feat: str, value: float) -> str:
        mapping = {
            'has_ip_in_domain': 'Domain uses raw IP address',
            'has_at_symbol': 'URL contains "@" symbol which can obscure real destination',
            'suspicious_char_ratio': 'High proportion of suspicious characters',
            'is_https': 'URL is not using HTTPS',
            'redirect_count': 'URL performs multiple redirects',
            'is_shortened_url': 'URL appears to be shortened',
            'idn_homograph_flag': 'Punycode/IDN detected – possible homograph attack',
            'tld_risk_score': 'Top-level domain is frequently abused',
            'virustotal_blacklisted': 'VirusTotal reports malicious votes',
            'has_redirect_js': 'Page contains JavaScript redirect code',
            'onmouse_over': 'Suspicious onmouseover event detected',
            'pop_up_window': 'Page opens pop-up windows',
            'has_frame_tag': 'Hidden frame/iframe present',
            'domain_age_days': 'Domain is very new',
            'days_to_expiry': 'Domain registration expires soon',
            'registration_span_days': 'Domain registered for very short period',
            'days_since_last_update': 'Domain was modified very recently',
            'non_standard_port': 'URL uses a non-standard port',
            'dangerous_file_ext': 'File extension is dangerous',
            'path_depth': 'URL path depth is suspicious',
            'gibberish_token_ratio': 'URL contains gibberish-looking strings',
        }
        return mapping.get(feat)


# ----------------------------------------------------------------------
# Quick self-test / demonstration (non-executed when imported)
# ----------------------------------------------------------------------
if __name__ == '__main__':
    detector = ThreatAdaptiveHeuristicDetector()
    demo_urls: List[str] = [
        'https://sec.gov.ng',
        'https://google.com',
        'http://163.142.92.92:58268/bin.sh'
        # 'bit.ly/3abcxyz',
        # '192.168.0.1/verify',
        # 'very-long-domain-name-with-lots-of-hyphens-and-dots.example.tk',
    ]

    for u in demo_urls:
        result = detector.analyse(u)
        print(json.dumps(result, indent=2)) 