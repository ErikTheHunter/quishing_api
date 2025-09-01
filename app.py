from flask import Flask, request, jsonify
import pandas as pd
import re
import math
import tldextract
from urllib.parse import urlparse
import joblib
from catboost import CatBoostClassifier
import yaml
from pathlib import Path
from pprint import pprint
import time
import os
import requests
from datetime import datetime, timedelta
from heuristic_phishing_detector import ThreatAdaptiveHeuristicDetector

app = Flask(__name__)

# --- Helper lists from original code ---
SUSPICIOUS_KEYWORDS = [
    'login', 'update', 'free', 'verify', 'secure', 'account', 'bank', 'confirm', 'password', 'signin', 'pay', 'payment'
]
URL_SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'shorte.st'
]
PHISHY_TLDS = ['.xyz', '.top', '.ru', '.tk', '.ml', '.ga', '.cf', '.gq']

# --- Original feature extraction functions ---
def url_length(url):
    return len(url)

def count_dots(url):
    return url.count('.')

def count_subdomains(url):
    ext = tldextract.extract(url)
    if ext.subdomain == '':
        return 0
    return len(ext.subdomain.split('.'))

def has_ip_address(url):
    ipv4 = re.search(r'://(\d{1,3}\.){3}\d{1,3}([/:]|$)', url)
    ipv6 = re.search(r'://\[[0-9a-fA-F:]+\]', url)
    return int(bool(ipv4 or ipv6))

def has_suspicious_keywords(url):
    url_lower = url.lower()
    return int(any(word in url_lower for word in SUSPICIOUS_KEYWORDS))

def count_special_chars(url):
    chars = '-@=_/?&%#'
    return sum(url.count(c) for c in chars)

def has_https(url):
    return int(url.lower().startswith('https://'))

def url_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    entropy = -sum([p * math.log2(p) for p in prob]) if prob else 0
    return entropy

def get_tld(url):
    ext = tldextract.extract(url)
    return '.' + ext.suffix if ext.suffix else ''

def tld_is_phishy(url):
    tld = get_tld(url)
    return int(tld in PHISHY_TLDS)

def path_length(url):
    parsed = urlparse(url)
    return len(parsed.path)

def path_level(url):
    parsed = urlparse(url)
    return len([p for p in parsed.path.split('/') if p])

def uses_url_shortener(url):
    netloc = urlparse(url).netloc.lower()
    return int(any(shortener in netloc for shortener in URL_SHORTENERS))

def has_homograph(url):
    try:
        url.encode('ascii')
        return 0
    except UnicodeEncodeError:
        return 1

def has_multiple_slash_after_domain(url):
    match = re.search(r'^[a-z]+://[^/]+//', url)
    return int(bool(match))

def https_in_hostname(url):
    netloc = urlparse(url).netloc.lower()
    return int('https' in netloc)

def count_numeric_chars(url):
    return sum(c.isdigit() for c in url)

def query_length(url):
    parsed = urlparse(url)
    return len(parsed.query)

def query_component_count(url):
    parsed = urlparse(url)
    if parsed.query == '':
        return 0
    return len(parsed.query.split('&'))

def brand_in_subdomain_or_path(url):
    ext = tldextract.extract(url)
    subdomain = ext.subdomain.lower()
    path = urlparse(url).path.lower()
    for brand in SUSPICIOUS_KEYWORDS:
        if brand in subdomain or brand in path:
            return 1
    return 0

def unusual_subdomains(url):
    return int(count_subdomains(url) > 2)

def extract_lexical_features(df):
    """Extract lexical features from a DataFrame of URLs."""
    df['url_length'] = df['url'].apply(url_length)
    df['num_dots'] = df['url'].apply(count_dots)
    df['num_subdomains'] = df['url'].apply(count_subdomains)
    df['has_ip'] = df['url'].apply(has_ip_address)
    df['has_suspicious_keywords'] = df['url'].apply(has_suspicious_keywords)
    df['special_char_count'] = df['url'].apply(count_special_chars)
    df['has_https'] = df['url'].apply(has_https)
    df['url_entropy'] = df['url'].apply(url_entropy)
    df['tld'] = df['url'].apply(get_tld)
    df['tld_is_phishy'] = df['url'].apply(tld_is_phishy)
    df['path_length'] = df['url'].apply(path_length)
    df['path_level'] = df['url'].apply(path_level)
    df['uses_shortener'] = df['url'].apply(uses_url_shortener)
    df['has_homograph'] = df['url'].apply(has_homograph)
    df['multiple_slash_after_domain'] = df['url'].apply(has_multiple_slash_after_domain)
    df['https_in_hostname'] = df['url'].apply(https_in_hostname)
    df['numeric_char_count'] = df['url'].apply(count_numeric_chars)
    df['query_length'] = df['url'].apply(query_length)
    df['query_component_count'] = df['url'].apply(query_component_count)
    df['brand_in_subdomain_or_path'] = df['url'].apply(brand_in_subdomain_or_path)
    df['unusual_subdomains'] = df['url'].apply(unusual_subdomains)
    return df

# --- Enhanced feature extraction from Jupyter notebook ---
class ConfigurableFeatureExtractor:
    def __init__(self, threat_config):
        self.whois_cache = {}  # Cache WHOIS results for speed
        self.threat_config = threat_config
        if 'threat_intelligence' not in threat_config or 'tld_categories' not in threat_config['threat_intelligence']:
            raise KeyError("Invalid threat intelligence configuration: 'tld_categories' missing")
        self.tld_categories = threat_config['threat_intelligence']['tld_categories']
        self.trusted_domains = self._flatten_trusted_domains()
        self.phishing_indicators = threat_config['threat_intelligence']['phishing_indicators']
        
    def _flatten_trusted_domains(self):
        """Flatten trusted domains from all categories into a single set"""
        all_domains = set()
        for category, domains in self.threat_config['threat_intelligence']['trusted_domains'].items():
            all_domains.update(domains)
        return all_domains
        
    def get_tld_risk_score(self, tld):
        tld = tld.lower()
        for category, category_info in self.tld_categories.items():
            if tld in category_info['tlds']:
                return category_info['risk_score']
        return 0.5
        
    def extract_domain_trust_score(self, url):
        try:
            ext = tldextract.extract(url)
            domain = ext.registered_domain.lower()
            tld = '.' + ext.suffix.lower()
            tld_risk = self.get_tld_risk_score(tld)
            tld_trust = 1 - tld_risk
            domain_trust_bonus = 0.3 if domain in self.trusted_domains else 0
            trust_score = min(tld_trust + domain_trust_bonus, 1.0)
            return trust_score
        except Exception:
            return 0.3
    
    def is_suspicious_domain_pattern(self, url):
        try:
            ext = tldextract.extract(url)
            domain = ext.registered_domain.lower()
            subdomain = ext.subdomain.lower()
            brand_names = self.phishing_indicators['brand_impersonation']
            suspicious_keywords = self.phishing_indicators['suspicious_keywords']
            suspicious_indicators = [
                any(brand in subdomain for brand in brand_names),
                any(brand in domain for brand in brand_names) and domain not in self.trusted_domains,
                len(subdomain.split('.')) > 3 if subdomain else False,
                bool(re.search(r'\d{3,}', domain)),
                any(keyword in domain for keyword in suspicious_keywords),
                len(domain) > 25,
                self.get_tld_risk_score('.' + ext.suffix.lower()) > 0.7 and len(domain) > 15
            ]
            return int(any(suspicious_indicators))
        except Exception:
            return 1
    
    def calculate_url_complexity_score(self, url):
        try:
            length_score = min(len(url) / 100, 1.0)
            special_chars = sum(1 for c in url if c in '!@#$%^&*()+=[]{}|;:,.<>?')
            special_score = min(special_chars / 20, 1.0)
            parsed = urlparse(url)
            path_levels = len([p for p in parsed.path.split('/') if p])
            path_score = min(path_levels / 10, 1.0)
            query_params = len(parsed.query.split('&')) if parsed.query else 0
            query_score = min(query_params / 10, 1.0)
            complexity = (length_score + special_score + path_score + query_score) / 4
            return complexity
        except Exception:
            return 0.8

class EnsemblePredictor:
    """Dynamic ensemble weighting system from Chapter 4.7"""
    
    def __init__(self):
        self.base_weights = {
            'ml_models': 0.40,      # Machine Learning consensus
            'heuristic': 0.30,      # Heuristic analysis
            'virustotal': 0.30      # VirusTotal blacklist
        }
    
    def extract_virustotal_from_heuristic(self, heuristic_result):
        """Extract VirusTotal data from heuristic feature breakdown"""
        feature_breakdown = heuristic_result.get('feature_breakdown', {})
        
        # Check if VirusTotal was queried
        vt_blacklisted = feature_breakdown.get('virustotal_blacklisted', 0)
        
        if vt_blacklisted > 0:
            # VirusTotal detected malicious
            return {
                'source': 'virustotal',
                'is_malicious': True,
                'threat_score': vt_blacklisted / 100.0,  # Convert back to 0-1 scale
                'detection_available': True
            }
        elif 'virustotal_blacklisted' in feature_breakdown:
            # VirusTotal queried but clean
            return {
                'source': 'virustotal',
                'is_malicious': False,
                'threat_score': 0.0,
                'detection_available': True
            }
        else:
            # VirusTotal not available (API key missing or quota exceeded)
            return {
                'source': 'fallback',
                'is_malicious': False,
                'threat_score': 0.0,
                'detection_available': False
            }
    
    def calculate_ensemble_prediction(self, ml_results, heuristic_result, virustotal_result):
        """Calculate ensemble prediction with dynamic weighting from Chapter 4.7"""
        
        # Start with base weights
        weights = self.base_weights.copy()
        confidence_modifier = 1.0
        
        # Adjust for VirusTotal unavailability (Chapter 4.7 logic)
        if not virustotal_result.get('detection_available', False):
            # Redistribute VirusTotal weight to other components
            weights['ml_models'] += 0.25  # 40% -> 65%
            weights['heuristic'] += 0.05  # 30% -> 35%
            weights['virustotal'] = 0.0
            confidence_modifier = 0.85    # Reduce confidence by 15%
        
        # Authority-based weighting: boost VirusTotal when it flags malicious
        elif virustotal_result.get('is_malicious'):
            weights['virustotal'] *= 1.5   # Authority-based weighting from Chapter 4.7
        
        # Calculate ML consensus dynamically across available models
        ml_probs = []
        try:
            for model_name, model_info in (ml_results or {}).items():
                if isinstance(model_info, dict) and 'malicious_probability_percent' in model_info:
                    ml_probs.append(float(model_info['malicious_probability_percent']) / 100.0)
        except Exception:
            ml_probs = []

        if ml_probs:
            ml_consensus_prob = sum(ml_probs) / len(ml_probs)
        else:
            # If no ML probabilities are available, zero out ML weight
            weights['ml_models'] = 0.0
            ml_consensus_prob = 0.0

        # Normalize weights to sum to 1.0
        total_weight = sum(weights.values())
        if total_weight > 0:
            for key in weights:
                weights[key] /= total_weight
        
        # Calculate component scores
        ml_score = ml_consensus_prob * weights['ml_models']
        heuristic_score = (heuristic_result.get('phish_score', 0) / 100) * weights['heuristic']
        virustotal_score = virustotal_result.get('threat_score', 0) * weights['virustotal']
        
        # Final ensemble score
        ensemble_score = ml_score + heuristic_score + virustotal_score
        final_confidence = min(ensemble_score * confidence_modifier, 1.0)
        
        # Determine final prediction
        prediction = 'Malicious' if final_confidence > 0.5 else 'Benign'
        
        return {
            'prediction': prediction,
            'confidence_score': final_confidence * 100,  # Convert to percentage
            'component_weights': weights,
            'component_scores': {
                'ml_models': ml_score,
                'heuristic': heuristic_score,
                'virustotal': virustotal_score
            },
            'ml_consensus_probability': ml_consensus_prob * 100
        }

class ConfigurableRealTimePhishingDetector:
    def __init__(self, rf_model, cb_model, feature_columns, threat_config):
        self.rf_model = rf_model
        self.cb_model = cb_model
        self.feature_columns = feature_columns
        self.threat_config = threat_config
        self.feature_extractor = ConfigurableFeatureExtractor(threat_config)
        self.tld_categories = threat_config['threat_intelligence']['tld_categories']
        self.trusted_domains = self.feature_extractor.trusted_domains
        
    def _get_tld_trust_level(self, tld):
        for category, info in self.tld_categories.items():
            if tld in info['tlds']:
                trust_mapping = {
                    'very_high': 3,
                    'high': 2,
                    'medium': 1,
                    'medium_low': 0,
                    'low': 0,
                    'very_low': 0
                }
                return trust_mapping.get(info['trust_level'], 0)
        return 0
    
    def extract_features_fast(self, url, timeout=2):
        try:
            features = {col: 0 for col in self.feature_columns}
            features['URLLength'] = len(url)
            features['domain_trust_score'] = self.feature_extractor.extract_domain_trust_score(url)
            features['is_suspicious_pattern'] = self.feature_extractor.is_suspicious_domain_pattern(url)
            features['url_complexity_score'] = self.feature_extractor.calculate_url_complexity_score(url)
            ext = tldextract.extract(url)
            domain = ext.registered_domain.lower()
            tld = '.' + ext.suffix.lower()
            features['DomainLength'] = len(domain)
            features['NoOfSubDomain'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
            features['IsHTTPS'] = 1 if url.lower().startswith('https://') else 0
            features['tld_trust_level'] = self._get_tld_trust_level(tld)
            tld_risk_score = self.feature_extractor.get_tld_risk_score(tld)
            features['TLDLegitimateProb'] = 1 - tld_risk_score
            features['security_score'] = features['IsHTTPS'] * 0.3 + features['domain_trust_score'] * 0.7
            parsed = urlparse(url)
            features['NoOfQMarkInURL'] = url.count('?')
            features['NoOfAmpersandInURL'] = url.count('&')
            features['NoOfEqualsInURL'] = url.count('=')
            features['NoOfLettersInURL'] = sum(1 for c in url if c.isalpha())
            features['NoOfDegitsInURL'] = sum(1 for c in url if c.isdigit())
            features['LetterRatioInURL'] = features['NoOfLettersInURL'] / len(url) if len(url) > 0 else 0
            features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / len(url) if len(url) > 0 else 0
            special_chars = '!@#$%^&*()+=[]{}|;:,.<>?-_/'
            special_count = sum(1 for c in url if c in special_chars)
            features['NoOfOtherSpecialCharsInURL'] = special_count
            features['SpacialCharRatioInURL'] = special_count / len(url) if len(url) > 0 else 0
            features['URLSimilarityIndex'] = 100 if domain in self.trusted_domains else 50
            for col in self.feature_columns:
                if col not in features:
                    features[col] = 0
            return features
        except Exception as e:
            print(f"Warning: Feature extraction failed for {url}: {e}")
            return {col: 0 for col in self.feature_columns}
    
    def predict_url(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            features = self.extract_features_fast(url)
            feature_df = pd.DataFrame([features])
            feature_df = feature_df[self.feature_columns]
            rf_pred = self.rf_model.predict(feature_df)[0]
            rf_prob = self.rf_model.predict_proba(feature_df)[0][1] * 100  # Convert to percentage
            cb_pred = self.cb_model.predict(feature_df)[0]
            cb_prob = self.cb_model.predict_proba(feature_df)[0][1] * 100  # Convert to percentage
            label_map = {0: 'good', 1: 'bad'}
            results = {
                'url': url,
                'random_forest': {
                    'prediction': label_map[rf_pred],
                    'malicious_probability_percent': float(rf_prob)
                },
                'catboost': {
                    'prediction': label_map[cb_pred],
                    'malicious_probability_percent': float(cb_prob)
                }
            }
            return results
        except Exception as e:
            print(f'Error predicting URL {url}: {str(e)}')
            return {
                'url': url,
                'random_forest': {
                    'prediction': 'bad',
                    'malicious_probability_percent': 80.0
                },
                'catboost': {
                    'prediction': 'bad',
                    'malicious_probability_percent': 80.0
                }
            }

# --- Configuration creation and update logic ---
def create_threat_intelligence_config():
    """Create industry-standard configuration file"""
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)
    
    # Industry-standard threat intelligence configuration
    config = {
        'threat_intelligence': {
            'tld_categories': {
                'government': {
                    'tlds': ['.gov', '.mil', '.gov.uk', '.gouv.fr', '.gov.au'],
                    'risk_score': 0.05,
                    'trust_level': 'very_high'
                },
                'education': {
                    'tlds': ['.edu', '.ac.uk', '.edu.au', '.ac.in'],
                    'risk_score': 0.10,
                    'trust_level': 'high'
                },
                'commercial_reputable': {
                    'tlds': ['.com', '.org', '.net'],
                    'risk_score': 0.30,
                    'trust_level': 'medium'
                },
                'free_domains': {
                    'tlds': ['.tk', '.ml', '.ga', '.cf'],
                    'risk_score': 0.90,
                    'trust_level': 'very_low'
                },
                'suspicious_new': {
                    'tlds': ['.xyz', '.top', '.click', '.download', '.zip'],
                    'risk_score': 0.75,
                    'trust_level': 'low'
                },
                'geographic_concern': {
                    'tlds': ['.ru', '.cn'],
                    'risk_score': 0.60,
                    'trust_level': 'medium_low'
                }
            },
            'trusted_domains': {
                'major_tech': [
                    'google.com', 'youtube.com', 'microsoft.com', 'apple.com',
                    'amazon.com', 'facebook.com', 'instagram.com', 'twitter.com'
                ],
                'development': [
                    'github.com', 'stackoverflow.com', 'gitlab.com'
                ],
                'media_news': [
                    'wikipedia.org', 'bbc.com', 'cnn.com', 'reuters.com'
                ],
                'business': [
                    'linkedin.com', 'salesforce.com', 'adobe.com'
                ]
            },
            'phishing_indicators': {
                'suspicious_keywords': [
                    'login', 'signin', 'verify', 'update', 'secure', 'account',
                    'suspended', 'confirm', 'validate', 'authentication',
                    'payment', 'billing', 'urgent', 'expire', 'suspended'
                ],
                'brand_impersonation': [
                    'paypal', 'amazon', 'google', 'microsoft', 'apple',
                    'facebook', 'instagram', 'netflix', 'spotify'
                ]
            },
            'update_settings': {
                'cache_duration_hours': 6,
                'threat_feed_update_frequency': 'daily'
            }
        }
    }
    
    config_path = config_dir / "threat_intelligence.yaml"
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, indent=2)
    
    return config_path

# Load or create configuration
config_path = Path('config/threat_intelligence.yaml')
cache_duration_hours = 6  # Default, in case config loading fails
try:
    # Check if file exists and is fresh
    if config_path.exists():
        file_age_hours = (time.time() - os.path.getmtime(config_path)) / 3600
        # Load config to get cache duration
        with open(config_path, 'r') as f:
            temp_config = yaml.safe_load(f)
        cache_duration_hours = temp_config.get('threat_intelligence', {}).get('update_settings', {}).get('cache_duration_hours', 6)
        if file_age_hours > cache_duration_hours:
            print(f"Configuration file is stale (age: {file_age_hours:.2f} hours > {cache_duration_hours} hours). Regenerating...")
            config_path = create_threat_intelligence_config()
    else:
        print("Configuration file not found. Creating new configuration...")
        config_path = create_threat_intelligence_config()

    # Load configuration
    with open(config_path, 'r') as f:
        THREAT_CONFIG = yaml.safe_load(f)
    if not THREAT_CONFIG or 'threat_intelligence' not in THREAT_CONFIG or 'tld_categories' not in THREAT_CONFIG['threat_intelligence']:
        raise KeyError("Invalid or missing 'threat_intelligence' or 'tld_categories' in configuration file")
except FileNotFoundError:
    print("Configuration file could not be created or loaded. Creating new configuration...")
    config_path = create_threat_intelligence_config()
    with open(config_path, 'r') as f:
        THREAT_CONFIG = yaml.safe_load(f)
except yaml.YAMLError as e:
    raise yaml.YAMLError(f"Error parsing threat intelligence configuration: {e}")

# Try to load evaluation feature columns for original models
ORIG_FEATURE_COLUMNS = None
try:
    ORIG_FEATURE_COLUMNS = joblib.load('/home/ace/study/tj_notes/phishing_detection_ml/models/feature_columns.pkl')
    if not isinstance(ORIG_FEATURE_COLUMNS, (list, tuple)):
        ORIG_FEATURE_COLUMNS = None
except Exception as e:
    ORIG_FEATURE_COLUMNS = None
    print(f"Warning: Could not load evaluation feature columns: {e}")

# Load original models
rf_model_orig = None
cb_model_orig = None
dt_model_orig = None
try:
    rf_model_orig = joblib.load('models/rf_model.joblib')
except Exception as e:
    print(f"Warning: rf_model.joblib could not be loaded: {e}")
try:
    cb_model_orig = CatBoostClassifier()
    cb_model_orig.load_model('models/cb_model.cbm')
except Exception as e:
    cb_model_orig = None
    print(f"Warning: cb_model.cbm could not be loaded: {e}")
try:
    dt_model_orig = joblib.load('models/df_model.joblib')
except Exception as e:
    dt_model_orig = None
    print(f"Warning: df_model.joblib (Decision Tree) could not be loaded: {e}")

# ------------------- New: Heuristic detector -------------------
# API keys can be supplied via environment variables (optional)
heuristic_detector = ThreatAdaptiveHeuristicDetector(
    vt_key=os.environ.get('VT_API_KEY'),
    whoxy_key=os.environ.get('WHOXY_API_KEY'),
    opr_key=os.environ.get('OPR_API_KEY'),
    aggregation="additive"
)

print('######################')
print('Heuristic detector initialized; API key presence:',
      bool(os.environ.get('VT_API_KEY')),
      bool(os.environ.get('WHOXY_API_KEY')),
      bool(os.environ.get('OPR_API_KEY')))
print('######################')

# ---------------------------------------------------------------

VT_CACHE = {}
VT_CACHE_TTL = timedelta(hours=24)


def _get_virustotal_result(url: str) -> dict:
    """Query VirusTotal v3 for the URL's domain. Returns a standardized dict.

    Falls back to a 'source': 'fallback' object when no key or on error.
    """
    try:
        vt_key = os.environ.get('VT_API_KEY')
        if not vt_key:
            return {
                'source': 'fallback',
                'is_malicious': False,
                'threat_score': 0.0,
                'detection_ratio': 'N/A',
                'scan_date': None,
                'permalink': None,
                'detection_available': False
            }

        parsed = urlparse(url)
        domain = tldextract.extract(url).registered_domain or parsed.netloc.split(':')[0]
        if not domain:
            return {
                'source': 'fallback',
                'is_malicious': False,
                'threat_score': 0.0,
                'detection_ratio': 'N/A',
                'scan_date': None,
                'permalink': None,
                'detection_available': False
            }

        # Check cache
        now = datetime.utcnow()
        cached = VT_CACHE.get(domain)
        if cached and (now - cached['timestamp']) < VT_CACHE_TTL:
            return cached['result']

        headers = {'x-apikey': vt_key}
        resp = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}', headers=headers, timeout=6)
        if resp.status_code != 200:
            return {
                'source': 'fallback',
                'is_malicious': False,
                'threat_score': 0.0,
                'detection_ratio': 'N/A',
                'scan_date': None,
                'permalink': None,
                'detection_available': False
            }

        data = resp.json().get('data', {})
        attrs = data.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        positives = int(stats.get('malicious', 0))
        total = sum(int(v) for v in stats.values()) if stats else 0
        threat_score = (positives / total) if total else 0.0

        result = {
            'source': 'virustotal',
            'is_malicious': positives > 0,
            'threat_score': threat_score,
            'detection_ratio': f"{positives}/{total}",
            'scan_date': attrs.get('last_analysis_date'),
            'permalink': f"https://www.virustotal.com/gui/domain/{domain}",
            'detection_available': True
        }

        # Save to cache
        VT_CACHE[domain] = {'timestamp': now, 'result': result}
        return result
    except Exception as e:
        print(f"VirusTotal lookup error: {e}")
        return {
            'source': 'fallback',
            'is_malicious': False,
            'threat_score': 0.0,
            'detection_ratio': 'N/A',
            'scan_date': None,
            'permalink': None,
            'detection_available': False
        }

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        url = data['url']

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        df_features = extract_lexical_features(pd.DataFrame({'url': [url]}))
        # Ensure numeric features are float (CatBoost expects float, not int/bool)
        numeric_cols = [c for c in df_features.columns if c not in ['url', 'tld']]
        df_features[numeric_cols] = df_features[numeric_cols].apply(pd.to_numeric, errors='coerce').fillna(0.0).astype('float64')
        if 'tld' in df_features.columns:
            df_features['tld'] = df_features['tld'].astype('object')

        # Helper to align features to a model's expected columns
        def _align_X(features_df, expected_cols):
            aligned = features_df.copy()
            for col in expected_cols:
                if col not in aligned.columns:
                    aligned[col] = 0
            return aligned[expected_cols]

        # Build X for RF/CB/DT based on each model's expected feature names
        X = None
        if rf_model_orig is not None and hasattr(rf_model_orig, 'feature_names_in_'):
            X = _align_X(df_features, list(rf_model_orig.feature_names_in_))
        else:
            feature_cols = [col for col in df_features.columns if col not in ['url', 'tld']]
            X = df_features[feature_cols]

        rf_label = None
        cb_label = None
        rf_prob = None
        cb_prob = None
        dt_prob = None

        if rf_model_orig is not None:
            rf_pred = rf_model_orig.predict(X)[0]
            rf_prob = rf_model_orig.predict_proba(X)[0][1] * 100
        if cb_model_orig is not None:
            cb_pred = cb_model_orig.predict(X)[0]
            cb_prob = cb_model_orig.predict_proba(X)[0][1] * 100
        if dt_model_orig is not None:
            try:
                dt_pred = dt_model_orig.predict(X)[0]
                if hasattr(dt_model_orig, 'predict_proba'):
                    dt_prob = dt_model_orig.predict_proba(X)[0][1] * 100
                else:
                    dt_prob = float(dt_pred) * 100.0
            except Exception as e:
                print(f"Decision Tree prediction error: {e}")

        label_map = {0: 'good', 1: 'bad'}
        if rf_prob is not None:
            rf_label = label_map[rf_pred]
        if cb_prob is not None:
            cb_label = label_map[cb_pred]
        # Decision tree label mapping will use predicted class if proba not available

        heuristic_result = heuristic_detector.analyse(url)
        
        # Prepare ML results for ensemble (include only available models)
        ml_results = {}
        if rf_prob is not None:
            ml_results['random_forest'] = {
                'prediction': rf_label,
                'malicious_probability_percent': float(rf_prob)
            }
        if cb_prob is not None:
            ml_results['catboost'] = {
                'prediction': cb_label,
                'malicious_probability_percent': float(cb_prob)
            }
        
        # Prefer direct VirusTotal lookup; gracefully fall back to heuristic-derived signal
        virustotal_result = _get_virustotal_result(url)
        if not virustotal_result.get('detection_available'):
            virustotal_result = ensemble_predictor.extract_virustotal_from_heuristic(heuristic_result)
        
        # Calculate ensemble prediction
        ensemble_result = ensemble_predictor.calculate_ensemble_prediction(
            ml_results, heuristic_result, virustotal_result
        )
        
        response_payload = {
            'url': url,
            'ensemble': ensemble_result,
            'virustotal': virustotal_result,
            'heuristic': heuristic_result
        }
        if rf_prob is not None:
            response_payload['random_forest'] = {
                'prediction': rf_label,
                'malicious_probability_percent': float(rf_prob)
            }
        if cb_prob is not None:
            response_payload['catboost'] = {
                'prediction': cb_label,
                'malicious_probability_percent': float(cb_prob)
            }
        if dt_prob is not None:
            response_payload['decision_tree'] = {
                'prediction': label_map[int(dt_pred)] if 'dt_pred' in locals() else 'bad',
                'malicious_probability_percent': float(dt_prob)
            }
        return jsonify(response_payload)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)