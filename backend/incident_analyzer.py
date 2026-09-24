"""
AI-Powered Network Security Incident Analysis System

Module:
    Incident Analyzer

Pipeline:

    Security Log
          ↓
    NLP Analyzer
          ↓
    XGBoost Predictor
          ↓
    Risk Analyzer
          ↓
    Complete Incident Result

The NLP and ML components intentionally receive
different representations of the same incident:

    NLP:
        security log text

    ML:
        UNSW-NB15 structured network-flow features
"""


try:

    from .nlp_analyzer import (
        analyze_security_log
    )

    from .ml_predictor import (
        predict_attack
    )

    from .risk_analyzer import (
        analyze_ml_result
    )

except ImportError:

    from nlp_analyzer import (
        analyze_security_log
    )

    from ml_predictor import (
        predict_attack
    )

    from risk_analyzer import (
        analyze_ml_result
    )


# ============================================================
# COMPLETE INCIDENT ANALYSIS
# ============================================================

def analyze_incident(
    security_log,
    network_record
):

    # --------------------------------------------------------
    # STEP 1
    # NLP
    # --------------------------------------------------------

    nlp_result = analyze_security_log(
        security_log
    )

    # --------------------------------------------------------
    # STEP 2
    # MACHINE LEARNING
    # --------------------------------------------------------

    ml_result = predict_attack(
        network_record
    )

    # --------------------------------------------------------
    # STEP 3
    # RISK
    # --------------------------------------------------------

    risk_result = analyze_ml_result(
        ml_result
    )

    # --------------------------------------------------------
    # STEP 4
    # COMBINE RESULTS
    # --------------------------------------------------------

    complete_result = {

        "security_log":
            security_log,

        "nlp_analysis": {

            "timestamp":
                nlp_result.get(
                    "timestamp"
                ),

            "source_ip":
                nlp_result.get(
                    "source_ip"
                ),

            "destination_ip":
                nlp_result.get(
                    "destination_ip"
                ),

            # Backward-compatible field
            "ip_address":
                nlp_result.get(
                    "ip_address"
                ),

            "port":
                nlp_result.get(
                    "port"
                ),

            "protocol":
                nlp_result.get(
                    "protocol"
                ),

            "username":
                nlp_result.get(
                    "username"
                ),

            "service":
                nlp_result.get(
                    "service"
                ),

            "connection_state":
                nlp_result.get(
                    "connection_state"
                ),

            "event":
                nlp_result.get(
                    "event"
                ),

            "severity":
                nlp_result.get(
                    "severity"
                ),

            "log_length":
                nlp_result.get(
                    "log_length"
                ),

            "extraction_status":
                nlp_result.get(
                    "extraction_status",
                    {}
                )
        },

        "ml_prediction": {

            "predicted_attack":
                ml_result[
                    "predicted_attack"
                ],

            "confidence":
                ml_result[
                    "confidence"
                ],

            "probabilities":
                ml_result[
                    "probabilities"
                ]
        },

        "risk_analysis": {

            "base_risk":
                risk_result[
                    "base_risk"
                ],

            "predicted_attack":
                risk_result[
                    "predicted_attack"
                ],

            "confidence":
                risk_result[
                    "confidence"
                ],

            "risk_score":
                risk_result[
                    "risk_score"
                ],

            "severity":
                risk_result[
                    "severity"
                ]
        }
    }

    return complete_result


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    sample_log = (
        "2026-09-24 07:30:10 "
        "Possible port scan detected "
        "from 192.168.1.50 "
        "to 10.0.0.12 "
        "targeting port 443 using TCP."
    )

    # This test requires a valid UNSW-NB15 record.
    print(
        "Incident analyzer module loaded successfully."
    )
    print(
        "Use test_api.py to test the complete pipeline."
    )