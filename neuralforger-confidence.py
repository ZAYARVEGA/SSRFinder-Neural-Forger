#!/usr/bin/env python3
"""
Neural Forger - Confidence Scoring Engine (Extension)

Extends SSRFinder's confidence_calculator with combined ML+injection
scoring. Uses SSRFinder's base confidence logic and adds weighted
ML integration for unified vulnerability assessment.
"""

from typing import Tuple, Optional, Dict, Any

# Import SSRFinder's base confidence logic
from confidence_calculator import calculate_confidence as ssrf_calculate_confidence

# Weight constants
ML_WEIGHT = 0.30
INJECTION_WEIGHT = 0.70


class ConfidenceResult:
    """Structured confidence assessment result."""

    def __init__(
        self,
        injection_confidence: float,
        injection_level: str,
        injection_reason: str,
        ml_confidence: Optional[float] = None,
        combined_confidence: Optional[float] = None,
    ):
        self.injection_confidence = injection_confidence
        self.injection_level = injection_level
        self.injection_reason = injection_reason
        self.ml_confidence = ml_confidence
        self.combined_confidence = combined_confidence

    @property
    def severity(self) -> str:
        """Determine severity label from combined or injection confidence."""
        score = self.combined_confidence if self.combined_confidence is not None else self.injection_confidence
        if score >= 90.0:
            return "CRITICAL"
        if score >= 75.0:
            return "HIGH"
        if score >= 50.0:
            return "MEDIUM"
        if score >= 25.0:
            return "LOW"
        return "INFO"

    @property
    def is_vulnerable(self) -> bool:
        """Whether the combined assessment indicates vulnerability."""
        score = self.combined_confidence if self.combined_confidence is not None else self.injection_confidence
        return score >= 50.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "injection_confidence": round(self.injection_confidence, 1),
            "injection_level": self.injection_level,
            "injection_reason": self.injection_reason,
            "ml_confidence": round(self.ml_confidence, 1) if self.ml_confidence is not None else None,
            "combined_confidence": round(self.combined_confidence, 1) if self.combined_confidence is not None else None,
            "severity": self.severity,
            "is_vulnerable": self.is_vulnerable,
        }


# Extended injection confidence mapping with numeric scores
# Maps (status_code_category, has_size_diff) -> (numeric_confidence, level, reason)
_CONFIDENCE_MAP = {
    (200, True):   (92.0, "HIGH",        "Status 200 with significant response size difference"),
    (200, False):  (35.0, "LOW",         "Status 200 but no significant response difference"),
    (201, True):   (78.0, "MEDIUM-HIGH", "Status 201 with response size difference"),
    (202, True):   (75.0, "MEDIUM-HIGH", "Status 202 with response size difference"),
    (301, True):   (70.0, "MEDIUM-HIGH", "Redirect (301) with size difference"),
    (302, True):   (72.0, "MEDIUM-HIGH", "Redirect (302) with size difference"),
    (303, True):   (68.0, "MEDIUM",      "Redirect (303) with size difference"),
    (307, True):   (72.0, "MEDIUM-HIGH", "Redirect (307) with size difference"),
    (308, True):   (72.0, "MEDIUM-HIGH", "Redirect (308) with size difference"),
    (401, True):   (55.0, "MEDIUM",      "Access denied (401) - server processed internal request"),
    (403, True):   (55.0, "MEDIUM",      "Forbidden (403) - server processed internal request"),
    (404, True):   (30.0, "LOW-MEDIUM",  "Not found (404) - possible internal connection"),
    (500, True):   (25.0, "LOW",         "Server error (500) - possible failed SSRF attempt"),
    (502, True):   (28.0, "LOW",         "Bad gateway (502) - possible backend SSRF interaction"),
    (503, True):   (20.0, "LOW",         "Service unavailable (503)"),
    (504, True):   (22.0, "LOW",         "Gateway timeout (504) - possible slow SSRF target"),
}


def calculate_injection_confidence(
    status_code: Optional[int],
    size_diff_percent: float,
    response_time_ms: Optional[float] = None,
) -> Tuple[float, str, str]:
    """
    Calculate confidence from injection test response characteristics.

    Enhanced version that provides numeric confidence scores for ML integration.

    Args:
        status_code: HTTP response status code (None if connection failed).
        size_diff_percent: Percentage difference from baseline response size.
        response_time_ms: Response time in milliseconds (optional).

    Returns:
        Tuple of (numeric_confidence, level_string, reason_string).
    """
    if status_code is None:
        return 5.0, "NONE", "Connection failed - target unreachable"

    has_diff = size_diff_percent > 10.0

    # Check exact match first
    key = (status_code, has_diff)
    if key in _CONFIDENCE_MAP:
        return _CONFIDENCE_MAP[key]

    # Category fallbacks
    if 200 <= status_code < 300 and has_diff:
        return 70.0, "MEDIUM-HIGH", f"Success status ({status_code}) with size difference"
    if 300 <= status_code < 400 and has_diff:
        return 60.0, "MEDIUM", f"Redirect status ({status_code}) with size difference"
    if 400 <= status_code < 500:
        return 10.0, "VERY-LOW", f"Client error ({status_code}) - likely false positive"
    if 500 <= status_code < 600 and has_diff:
        return 22.0, "LOW", f"Server error ({status_code}) with size difference"

    # Time-based bonus
    if response_time_ms and response_time_ms > 5000:
        return 40.0, "LOW-MEDIUM", f"Significant response delay ({response_time_ms:.0f}ms)"

    return 5.0, "NONE", "No significant indicators detected"


def calculate_combined_confidence(
    injection_confidence: float,
    ml_confidence: Optional[float] = None,
    ml_weight: float = ML_WEIGHT,
    injection_weight: float = INJECTION_WEIGHT,
) -> float:
    """
    Compute weighted combined confidence from ML and injection scores.

    Args:
        injection_confidence: Injection test confidence (0-100).
        ml_confidence: ML prediction confidence (0-100), or None.
        ml_weight: Weight for ML score (default 0.30).
        injection_weight: Weight for injection score (default 0.70).

    Returns:
        Combined confidence score (0-100).
    """
    if ml_confidence is None:
        return injection_confidence

    combined = (ml_confidence * ml_weight) + (injection_confidence * injection_weight)
    return min(100.0, max(0.0, combined))


def build_confidence_result(
    status_code: Optional[int],
    size_diff_percent: float,
    response_time_ms: Optional[float] = None,
    ml_confidence: Optional[float] = None,
) -> ConfidenceResult:
    """
    Build a complete confidence assessment.

    Combines injection confidence calculation with optional ML confidence.

    Args:
        status_code: HTTP status code.
        size_diff_percent: Response size difference percentage.
        response_time_ms: Response time in milliseconds.
        ml_confidence: ML prediction confidence.

    Returns:
        ConfidenceResult with all scores populated.
    """
    inj_conf, inj_level, inj_reason = calculate_injection_confidence(
        status_code, size_diff_percent, response_time_ms,
    )

    combined = None
    if ml_confidence is not None:
        combined = calculate_combined_confidence(inj_conf, ml_confidence)

    return ConfidenceResult(
        injection_confidence=inj_conf,
        injection_level=inj_level,
        injection_reason=inj_reason,
        ml_confidence=ml_confidence,
        combined_confidence=combined,
    )
