"""
AI-Powered Network Security Incident Analysis System

Module:
    Risk Analyzer

Purpose:
    Calculate a project-defined risk score based on:

        Predicted Attack Category
        Model Confidence

Formula:

    Risk Score = Base Risk × Confidence

IMPORTANT:
    This is a project-defined heuristic.
    It is not a standardized cybersecurity framework.
"""


# ============================================================
# BASE RISK SCORES
# ============================================================

BASE_RISK_SCORES = {

    "Normal": 10,

    "Analysis": 35,

    "Reconnaissance": 45,

    "Fuzzers": 55,

    "Generic": 60,

    "DoS": 70,

    "Exploits": 80,

    "Backdoor": 85,

    "Shellcode": 90,

    "Worms": 95
}


# ============================================================
# SEVERITY
# ============================================================

def determine_severity(risk_score):

    if risk_score <= 30:
        return "LOW"

    if risk_score <= 60:
        return "MEDIUM"

    if risk_score <= 80:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# CALCULATE RISK
# ============================================================

def calculate_risk_score(
    predicted_attack,
    confidence
):

    if predicted_attack not in BASE_RISK_SCORES:

        raise ValueError(
            "Unknown attack category: "
            f"{predicted_attack}"
        )

    if confidence is None:

        raise ValueError(
            "Model confidence cannot be None."
        )

    try:

        confidence = float(
            confidence
        )

    except (
        TypeError,
        ValueError
    ):

        raise ValueError(
            "Confidence must be numeric."
        )

    if not 0 <= confidence <= 1:

        raise ValueError(
            "Confidence must be between 0 and 1."
        )

    base_risk = (
        BASE_RISK_SCORES[
            predicted_attack
        ]
    )

    risk_score = (
        base_risk *
        confidence
    )

    risk_score = max(
        0,
        min(
            100,
            risk_score
        )
    )

    risk_score = round(
        risk_score,
        2
    )

    severity = determine_severity(
        risk_score
    )

    return {

        "predicted_attack":
            predicted_attack,

        "confidence":
            round(
                confidence,
                4
            ),

        "base_risk":
            base_risk,

        "risk_score":
            risk_score,

        "severity":
            severity
    }


# ============================================================
# ANALYZE ML RESULT
# ============================================================

def analyze_ml_result(
    ml_result
):

    if not isinstance(
        ml_result,
        dict
    ):

        raise TypeError(
            "ml_result must be a dictionary."
        )

    required = [
        "predicted_attack",
        "confidence"
    ]

    missing = [
        key
        for key in required
        if key not in ml_result
    ]

    if missing:

        raise ValueError(
            "ML result is missing: "
            f"{missing}"
        )

    return calculate_risk_score(
        predicted_attack=
            ml_result["predicted_attack"],

        confidence=
            ml_result["confidence"]
    )