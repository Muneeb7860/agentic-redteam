"""
SwishOS Anti-MCTS & Token Entropy Module (Python Counterpart)
Analyzes character Shannon entropy and trajectory N-Gram similarity.
"""

from __future__ import annotations
import math
import re
from typing import Dict, List, Set, Tuple

def compute_shannon_entropy(text: str) -> float:
    """Calculates character-level Shannon Entropy."""
    if not text:
        return 0.0
    frequencies: Dict[str, int] = {}
    for ch in text:
        frequencies[ch] = frequencies.get(ch, 0) + 1
    
    entropy = 0.0
    length = len(text)
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def get_ngrams(text: str, n: int = 3) -> Set[str]:
    """Extracts character N-grams from lowercased alphanumeric string."""
    normalized = re.sub(r'[^a-z0-9]', '', text.lower())
    return {normalized[i:i+n] for i in range(len(normalized) - n + 1)}

def compute_ngram_cosine_similarity(text_a: str, text_b: str) -> float:
    """Computes N-Gram Cosine Similarity between two strings."""
    if not text_a or not text_b:
        return 0.0
    set_a = get_ngrams(text_a)
    set_b = get_ngrams(text_b)
    
    if not set_a or not set_b:
        return 0.0
        
    intersection = len(set_a.intersection(set_b))
    return intersection / math.sqrt(len(set_a) * len(set_b))
