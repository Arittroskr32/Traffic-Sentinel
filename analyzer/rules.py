from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Any
import re


@dataclass
class Hit:
    category: str
    rule_id: Optional[str]
    target: str
    matched: str
    snippet: str


@dataclass
class ScanResult:
    ip: str
    score_total: int
    hits: List[Hit]


@dataclass
class Rule:
    category: str
    rule_id: Optional[str]
    targets: List[str]
    patterns: List[re.Pattern]
    # Always 1 (your requirement)
    score: int = 1


RequestLike = Dict[str, Any]
