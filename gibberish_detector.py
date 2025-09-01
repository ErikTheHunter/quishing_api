import re
import string
from typing import Tuple, Dict, Set
from pathlib import Path
import urllib.request
import json

class GibberishDetector:
    def __init__(self, dictionary_path: str = None, download_dictionary: bool = True):
        """
        On initialization of Gibberish Detector class, load it with English language words and 
        basic phonetic rules.
        """
        self.english_words: Set[str] = set()
        self._load_dictionary(dictionary_path, download_dictionary)
        
        # English phonetic patterns
        self.vowels = set('aeiouAEIOU')
        self.consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
        
        # Common english component clusters
        self.valid_initial_clusters = {
            'bl', 'br', 'cl', 'cr', 'dr', 'fl', 'fr', 'gl', 'gr', 'pl', 'pr', 'sc', 'sk', 'sl', 'sm', 'sn', 'sp', 
            'st', 'sw', 'tr', 'tw', 'th', 'sh', 'ch', 'wh', 'ph', 'gh', 'sch', 'scr', 'shr', 'spl', 'spr', 'str', 'thr'
        }
        
        self.valid_final_clusters = {
            'ck', 'ng', 'nk', 'nt', 'nd', 'mp', 'mb', 'st', 'sk', 'sp', 'th', 'sh', 'ch', 'gh', 'ph', 'ft', 'pt',
            'ct', 'xt', 'lt', 'rt', 'lk', 'rk', 'lm', 'rm', 'ln', 'rn', 'lp', 'rp', 'ls', 'rs', 'lf', 'rf'
        }
        
        # Rare letter combinations in English
        self.rare_combinations = {
            'qx', 'qz', 'qj', 'qk', 'qy', 'qw', 'xz', 'zx', 'jx', 'vx', 'wx', 'xj', 'xv', 'xw', 'bx', 'cx', 
            'dx', 'fx', 'gx', 'hx', 'jq', 'jz', 'kq', 'kx', 'mq', 'mx', 'pq', 'px', 'qb', 'qc', 'qd', 'qf',
            'qg', 'qh', 'ql', 'qm', 'qn', 'qp', 'qr', 'qs', 'qt', 'qv', 'tq', 'vq', 'wq', 'xb', 'xc', 'xd',
            'xf', 'xg', 'xh', 'xk', 'xl', 'xm', 'xn', 'xp', 'xq', 'xr', 'xs', 'xt', 'xu', 'xw', 'xy', 'zq',
            'zj', 'zx'
        }
        
        # Common English prefixes and suffixes
        self.common_prefixes = {
            'un', 're', 'in', 'dis', 'en', 'non', 'over', 'mis', 'sub', 'pre', 'inter', 'fore', 'de', 'trans',
            'super', 'semi', 'anti', 'mid', 'under', 'out', 'up', 'im', 'il', 'ir', 'auto', 'co', 'counter'
        }
        
        self.common_suffixes = {
            'ing', 'ed', 'er', 'est', 'ly', 'tion', 'sion', 'ness', 'ment', 'ful', 'less', 'able', 'ible',
            'ous', 'ive', 'age', 'ish', 'ize', 'ise', 'ward', 'wise', 'like', 'ship', 'hood', 'dom', 'fy'
        }
        
    def _load_dictionary(self, dictionary_path: str, download_dictionary: bool):
        """
        Helper class to load dictionary, the class if flexible enough to load from a custom 
        file, download from the internet or use a default fallback.
        """
        
        if dictionary_path and Path(dictionary_path).exists():
            # read custom dictionary file if provided 
            with open(dictionary_path, 'r', encoding='utf-8') as f:
                self.english_words = {line.strip().lower() for line in f if line.strip()}
        elif download_dictionary:
            # Download comprehensive dictionary
            try:
                # Comprehensive word list from SCOWL (Spell Checker Oriented Word Lists)
                url = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
                with urllib.request.urlopen(url, timeout=10) as response:
                    content = response.read().decode('utf-8')
                    self.english_words = {word.strip().lower() for word in content.split('\n') if word.strip()}
                print(f"Loaded {len(self.english_words)} words from online dictionary")
            except Exception as e:
                print(f"Failed to download dictionary: {e}")
                # Fallback to essential words
                self._load_fallback_dictionary()
        else:
            self._load_fallback_dictionary()
    
    def _load_fallback_dictionary(self):
        """Load a comprehensive fallback dictionary when downloads fails, This dictionary is as extracted from the web"""
        # More comprehensive word list for production use
        essential_words = """
        a about above after again against all almost alone along already also although always am among an and
        another any anybody anyone anything anyway anywhere appear around as ask at away back be became because
        become becomes becoming been before began behind being believe below between beyond big book both boy
        brought business but by call came can cannot car carry case change come could country course day did
        different do does done don't down during each early even ever every example eye face far feel few find
        first for found from get give go good got great group hand has have he head help her here high him his
        home how however i if important in into is it its just know large last left let life like line little
        long look made make man many may me might more most move much must my name need never new next night no
        not now number of off often old on once one only or other our out over own part people place point put
        right said same saw say school see seem seemed should show since small so some something sometimes still
        such take than that the their them then there these they thing think this those though three through
        time to today together too took two under until up us use used using very want was water way we well
        went were what when where which while who why will with within without work world would write year you
        young your
        """
        
        # Add common programming and technical terms
        technical_words = """
        algorithm computer software hardware program code data database system network internet website
        application development technology digital electronic automatic function method process procedure
        information technology science mathematics engineering physics chemistry biology medicine health
        education business management finance economics politics government society culture history geography
        language literature art music sport entertainment media communication transportation construction
        manufacturing agriculture environment energy resource material equipment tool instrument device
        machine engine motor vehicle aircraft ship train building structure design architecture construction
        """
        
        # Add common names and proper nouns (lowercase for consistency)
        common_names = """
        john mary james robert patricia jennifer michael william elizabeth david richard susan joseph thomas
        christopher charles daniel matthew anthony lisa nancy karen betty helen sandra donna carol ruth sharon
        michelle laura sarah kimberly deborah dorothy lisa nancy karen
        """
        
        all_words = essential_words + " " + technical_words + " " + common_names
        self.english_words = {word.strip().lower() for word in all_words.split() if word.strip()}
        print(f"Loaded {len(self.english_words)} fallback dictionary words")
    
    def _contains_numbers(self, text: str) -> bool:
        """Does the text contain numbers, returns boolean"""
        return any(char.isdigit() for char in text)
    
    def _contains_special_chars(self, text: str) -> bool:
        """Does the text contain special characters, returns boolean (this excludes basic punctuations)"""
        allowed_chars = set(string.ascii_letters + string.digits + " '-.")
        return any(char not in allowed_chars for char in text)
    
    def _excessive_repetition(self, text: str) -> Tuple[bool, int]:
        """Checks for excessive character repitition commong gibberish words"""
        import itertools
        max_consecutive = 0
        
        for char, group in itertools.groupby(text.lower()):
            consecutive_count = len(list(group))
            max_consecutive = max(max_consecutive, consecutive_count)
        
        # Allow up to 2 consecutive chars (like 'book', 'letter'), 3 for some cases like 'IEEE'
        excessive = max_consecutive > 3
        return excessive, max_consecutive
    
    def dictionary_check(self, word: str) -> Tuple[bool, str]:
        
        if not word or not isinstance(word, str):
            return False, "Empty or invalid input"
        
        # Clean the word
        clean_word = word.strip().lower()
        
        # Check for numbers
        if self._contains_numbers(clean_word):
            return False, "Contains numeric digits"
        
        # Check for special characters
        if self._contains_special_chars(clean_word):
            return False, "Contains special characters"
        
        # Check for excessive repetition
        excessive_rep, max_consec = self._excessive_repetition(clean_word)
        if excessive_rep:
            return False, f"Excessive character repetition ({max_consec} consecutive)"
        
        # Remove punctuation for analysis
        word_clean = ''.join(c for c in clean_word if c.isalpha())
        
        if not word_clean:
            return False, "No alphabetic characters"
        
        # Direct dictionary lookup
        if word_clean in self.english_words:
            return True, "Found in dictionary"
        
        # Check variations such as plural words, past tense, etc
        variations = [
            word_clean.rstrip('s'),  # plural
            word_clean.rstrip('ed'),  # past tense
            word_clean.rstrip('ing'),  # present participle
            word_clean.rstrip('er'),  # comparative
            word_clean.rstrip('est'),  # superlative
            word_clean.rstrip('ly'),  # adverb
        ]
        
        for variation in variations:
            if len(variation) > 2 and variation in self.english_words:
                return True, f"Root word '{variation}' found in dictionary"
        
        # Check for prefix/suffix combinations
        for prefix in self.common_prefixes:
            if word_clean.startswith(prefix) and len(word_clean) > len(prefix) + 2:
                root = word_clean[len(prefix):]
                if root in self.english_words:
                    return True, f"Prefix + root word found"
        
        for suffix in self.common_suffixes:
            if word_clean.endswith(suffix) and len(word_clean) > len(suffix) + 2:
                root = word_clean[:-len(suffix)]
                if root in self.english_words:
                    return True, f"Root word + suffix found"
        
        return False, "Not found in dictionary or common variations"
    
    def phonetic_analysis(self, word: str) -> Tuple[bool, float, Dict[str, any]]:
        """
        Advanced phonetic pattern analysis for English-like characteristics
        """
        if not word or not isinstance(word, str):
            return False, 0.0, {"error": "Invalid input"}
        
        clean_word = ''.join(c for c in word.lower() if c.isalpha())
        
        if not clean_word:
            return False, 0.0, {"error": "No alphabetic characters"}
        
        details = {}
        score = 0.0
        max_score = 10.0
        
        # 1. Check for numbers (immediate disqualification)
        if self._contains_numbers(word):
            return False, 0.0, {"error": "Contains numbers - definitely gibberish"}
        
        # 2. Excessive repetition check
        excessive_rep, max_consec = self._excessive_repetition(clean_word)
        if excessive_rep:
            return False, 0.0, {"error": f"Excessive repetition: {max_consec} consecutive characters"}
        elif max_consec <= 2:
            score += 1.0
            details['repetition_check'] = f"✓ Good repetition pattern (max {max_consec})"
        else:
            score += 0.5
            details['repetition_check'] = f"~ Acceptable repetition (max {max_consec})"
        
        # 3. Vowel distribution analysis
        vowel_count = sum(1 for c in clean_word if c in self.vowels)
        vowel_ratio = vowel_count / len(clean_word)
        
        if 0.25 <= vowel_ratio <= 0.55:
            score += 1.5
            details['vowel_analysis'] = f"✓ Optimal vowel ratio: {vowel_ratio:.2f}"
        elif 0.15 <= vowel_ratio <= 0.65:
            score += 1.0
            details['vowel_analysis'] = f"~ Acceptable vowel ratio: {vowel_ratio:.2f}"
        else:
            details['vowel_analysis'] = f"✗ Poor vowel ratio: {vowel_ratio:.2f}"
        
        # 4. Consonant cluster analysis
        consonant_violations = 0
        consonant_clusters = []
        
        # Find all consonant clusters
        i = 0
        while i < len(clean_word):
            if clean_word[i] in self.consonants:
                cluster = ""
                start_pos = i
                while i < len(clean_word) and clean_word[i] in self.consonants:
                    cluster += clean_word[i]
                    i += 1
                
                if len(cluster) > 1:
                    consonant_clusters.append((cluster, start_pos))
                    
                    # Check if cluster is valid based on position
                    if start_pos == 0:  # Initial position
                        if cluster not in self.valid_initial_clusters and len(cluster) > 3:
                            consonant_violations += 1
                    elif i == len(clean_word):  # Final position
                        if cluster not in self.valid_final_clusters and len(cluster) > 3:
                            consonant_violations += 1
                    else:  # Middle position - stricter rules
                        if len(cluster) > 2:
                            consonant_violations += 1
            else:
                i += 1
        
        # Score consonant clusters
        if consonant_violations == 0:
            score += 1.5
            details['consonant_clusters'] = f"✓ All clusters valid: {[c[0] for c in consonant_clusters]}"
        elif consonant_violations <= 1:
            score += 0.75
            details['consonant_clusters'] = f"~ Minor cluster issues: {consonant_violations} violations"
        else:
            details['consonant_clusters'] = f"✗ Multiple cluster violations: {consonant_violations}"
        
        # 5. Rare letter combination check
        rare_combo_count = 0
        found_combos = []
        
        for i in range(len(clean_word) - 1):
            bigram = clean_word[i:i+2]
            if bigram in self.rare_combinations:
                rare_combo_count += 1
                found_combos.append(bigram)
        
        if rare_combo_count == 0:
            score += 1.5
            details['rare_combinations'] = "✓ No rare letter combinations"
        elif rare_combo_count == 1:
            score += 0.5
            details['rare_combinations'] = f"~ One rare combination: {found_combos}"
        else:
            details['rare_combinations'] = f"✗ Multiple rare combinations: {found_combos}"
        
        # 6. Length and structure analysis
        length = len(clean_word)
        if 2 <= length <= 20:
            score += 1.0
            details['length_check'] = f"✓ Reasonable length: {length}"
        elif 1 <= length <= 25:
            score += 0.5
            details['length_check'] = f"~ Acceptable length: {length}"
        else:
            details['length_check'] = f"✗ Unusual length: {length}"
        
        # 7. Starting and ending letter analysis
        start_end_score = 0
        
        # Letters that rarely start English words
        rare_start = set('qxzj')
        if clean_word[0] not in rare_start:
            start_end_score += 0.5
        
        # Letters that rarely end English words
        rare_end = set('qxjvh')
        if clean_word[-1] not in rare_end:
            start_end_score += 0.5
        
        score += start_end_score
        details['start_end_analysis'] = f"Start/end appropriateness: {start_end_score}/1.0"
        
        # 8. Vowel-consonant alternation pattern
        alternations = 0
        total_transitions = len(clean_word) - 1
        
        for i in range(total_transitions):
            curr_is_vowel = clean_word[i] in self.vowels
            next_is_vowel = clean_word[i + 1] in self.vowels
            if curr_is_vowel != next_is_vowel:
                alternations += 1
        
        if total_transitions > 0:
            alternation_ratio = alternations / total_transitions
            if 0.4 <= alternation_ratio <= 0.8:
                score += 1.0
                details['alternation_pattern'] = f"✓ Good alternation: {alternation_ratio:.2f}"
            elif 0.2 <= alternation_ratio <= 0.9:
                score += 0.5
                details['alternation_pattern'] = f"~ Fair alternation: {alternation_ratio:.2f}"
            else:
                details['alternation_pattern'] = f"✗ Poor alternation: {alternation_ratio:.2f}"
        
        # 9. Morphological plausibility (prefix/suffix patterns)
        morph_score = 0
        has_common_prefix = any(clean_word.startswith(prefix) for prefix in self.common_prefixes)
        has_common_suffix = any(clean_word.endswith(suffix) for suffix in self.common_suffixes)
        
        if has_common_prefix or has_common_suffix:
            morph_score += 0.5
            details['morphology'] = f"✓ Has recognizable prefix/suffix patterns"
        else:
            details['morphology'] = "~ No obvious morphological patterns"
        
        score += morph_score
        
        # Calculate final assessment
        confidence = score / max_score
        is_probably_english = confidence >= 0.6  # Higher threshold for production
        
        details['total_score'] = f"{score:.1f}/{max_score}"
        details['confidence'] = f"{confidence:.3f}"
        
        return is_probably_english, confidence, details
    
    def analyze_word(self, word: str) -> Dict[str, any]:
        """
        Complete production-ready analysis
        """
        if not word or not isinstance(word, str):
            return {
                'word': word,
                'error': 'Invalid input',
                'final_decision': 'Invalid',
                'certainty': 'High'
            }
        
        # Dictionary analysis
        dict_result, dict_explanation = self.dictionary_check(word)
        
        # Phonetic analysis
        phonetic_result, confidence, phonetic_details = self.phonetic_analysis(word)
        
        # Production-ready decision logic
        if dict_result:
            final_decision = "English"
            certainty = "Very High"
            reasoning = "Confirmed in dictionary"
        elif not phonetic_result and confidence < 0.3:
            final_decision = "Gibberish"
            certainty = "Very High"
            reasoning = "Failed multiple phonetic tests"
        elif not phonetic_result and confidence < 0.5:
            final_decision = "Gibberish"
            certainty = "High"
            reasoning = "Poor phonetic patterns"
        elif phonetic_result and confidence >= 0.8:
            final_decision = "Likely English"
            certainty = "High"
            reasoning = "Strong phonetic patterns, not in dictionary"
        elif phonetic_result and confidence >= 0.6:
            final_decision = "Possibly English"
            certainty = "Medium"
            reasoning = "Some valid phonetic patterns"
        else:
            final_decision = "Likely Gibberish"
            certainty = "Medium-High"
            reasoning = "Weak phonetic patterns"
        
        return {
            'word': word,
            'dictionary': {
                'result': dict_result,
                'explanation': dict_explanation
            },
            'phonetic': {
                'result': phonetic_result,
                'confidence': confidence,
                'details': phonetic_details
            },
            'final_decision': final_decision,
            'certainty': certainty,
            'reasoning': reasoning
        }
