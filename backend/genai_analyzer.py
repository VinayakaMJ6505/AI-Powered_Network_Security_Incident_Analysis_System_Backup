"""
AI-Powered Network Security Incident Analysis System

Module:
    Incident Explanation Generator

Purpose:
    Convert the structured incident result into a
    human-readable explanation.

The module does not perform attack detection.
The XGBoost model remains responsible for prediction.
"""


# ============================================================
# SUMMARY
# ============================================================

def generate_summary(
    predicted_attack,
    confidence,
    event,
    risk_score,
    severity
):

    confidence_percent = (
        float(confidence) * 100
    )

    event_text = (
        event
        if event
        else "network traffic"
    )

    return (
        f"The system analyzed {event_text}. "
        f"The machine-learning model classified "
        f"the network behavior as "
        f"{predicted_attack} with "
        f"{confidence_percent:.2f}% confidence. "
        f"The project-defined risk score is "
        f"{risk_score:.2f}/100, resulting in "
        f"{severity} severity."
    )


# ============================================================
# TECHNICAL EXPLANATION
# ============================================================

def generate_technical_explanation(
    incident_result
):

    nlp = incident_result[
        "nlp_analysis"
    ]

    ml = incident_result[
        "ml_prediction"
    ]

    risk = incident_result[
        "risk_analysis"
    ]

    predicted_attack = ml[
        "predicted_attack"
    ]

    confidence = (
        float(
            ml["confidence"]
        ) * 100
    )

    risk_score = risk[
        "risk_score"
    ]

    severity = risk[
        "severity"
    ]

    event = nlp.get(
        "event"
    )

    protocol = nlp.get(
        "protocol"
    )

    service = nlp.get(
        "service"
    )

    state = nlp.get(
        "connection_state"
    )

    source_ip = nlp.get(
        "source_ip"
    )

    destination_ip = nlp.get(
        "destination_ip"
    )

    port = nlp.get(
        "port"
    )

    details = []

    if event:
        details.append(
            f"Detected event: {event}."
        )

    if protocol:
        details.append(
            f"Protocol: {protocol}."
        )

    if service:
        details.append(
            f"Service: {service}."
        )

    if state:
        details.append(
            f"Connection state: {state}."
        )

    if source_ip:
        details.append(
            f"Source IP: {source_ip}."
        )

    if destination_ip:
        details.append(
            f"Destination IP: {destination_ip}."
        )

    if port is not None:
        details.append(
            f"Port: {port}."
        )

    if not details:
        details.append(
            "The supplied security log did not "
            "contain additional network identifiers."
        )

    return (
        " ".join(details)
        + " "
        + (
            f"The XGBoost model predicted "
            f"{predicted_attack} with "
            f"{confidence:.2f}% confidence. "
        )
        + (
            f"The calculated project risk score is "
            f"{risk_score:.2f}/100 with "
            f"{severity} severity."
        )
    )


# ============================================================
# RECOMMENDATIONS
# ============================================================

def generate_recommendations(
    predicted_attack
):

    recommendations = {

        "Normal": [
            "Continue monitoring the network flow.",
            "Maintain normal security logging.",
            "Correlate future unusual activity with this event."
        ],

        "Analysis": [
            "Review the source traffic for unusual behavior.",
            "Inspect related network events.",
            "Correlate the event with other security logs."
        ],

        "Reconnaissance": [
            "Monitor the source for repeated scanning activity.",
            "Review targeted services and ports.",
            "Correlate the event with other reconnaissance activity."
        ],

        "Fuzzers": [
            "Monitor the source for repeated abnormal requests.",
            "Review the targeted service for malformed or unusual input.",
            "Correlate the event with other suspicious network activity."
        ],

        "Generic": [
            "Review the associated network flow.",
            "Inspect related security events.",
            "Monitor for repeated suspicious behavior."
        ],

        "DoS": [
            "Monitor traffic volume and request rates.",
            "Review affected services for availability issues.",
            "Correlate traffic with other denial-of-service indicators."
        ],

        "Exploits": [
            "Review the targeted service and exposed application.",
            "Inspect related requests for exploitation indicators.",
            "Check affected systems for unexpected behavior."
        ],

        "Backdoor": [
            "Review the affected host for unauthorized access.",
            "Inspect authentication and process activity.",
            "Correlate the event with other suspicious connections."
        ],

        "Shellcode": [
            "Review the affected host for abnormal execution activity.",
            "Inspect related application and system logs.",
            "Investigate correlated network connections."
        ],

        "Worms": [
            "Monitor for repeated connections to multiple hosts.",
            "Inspect affected systems for propagation indicators.",
            "Correlate network activity across hosts."
        ]
    }

    return recommendations.get(

        predicted_attack,

        [
            "Review the associated network traffic.",
            "Inspect related security logs.",
            "Continue monitoring for repeated activity."
        ]
    )


# ============================================================
# COMPLETE EXPLANATION
# ============================================================

def generate_incident_explanation(
    incident_result
):

    if not isinstance(
        incident_result,
        dict
    ):

        raise TypeError(
            "incident_result must be a dictionary."
        )

    required_sections = [

        "security_log",
        "nlp_analysis",
        "ml_prediction",
        "risk_analysis"
    ]

    missing_sections = [

        section

        for section in required_sections

        if section not in incident_result
    ]

    if missing_sections:

        raise ValueError(
            "Incident result is missing: "
            f"{missing_sections}"
        )

    nlp = incident_result[
        "nlp_analysis"
    ]

    ml = incident_result[
        "ml_prediction"
    ]

    risk = incident_result[
        "risk_analysis"
    ]

    predicted_attack = ml[
        "predicted_attack"
    ]

    confidence = ml[
        "confidence"
    ]

    risk_score = risk[
        "risk_score"
    ]

    severity = risk[
        "severity"
    ]

    event = nlp.get(
        "event",
        "Network traffic flow"
    )

    summary = generate_summary(

        predicted_attack=
            predicted_attack,

        confidence=
            confidence,

        event=
            event,

        risk_score=
            risk_score,

        severity=
            severity
    )

    technical_explanation = (
        generate_technical_explanation(
            incident_result
        )
    )

    recommendations = (
        generate_recommendations(
            predicted_attack
        )
    )

    return {

        "incident_summary":
            summary,

        "technical_explanation":
            technical_explanation,

        "detected_event":
            event,

        "predicted_attack":
            predicted_attack,

        "confidence":
            confidence,

        "risk_score":
            risk_score,

        "severity":
            severity,

        "source_ip":
            nlp.get("source_ip"),

        "destination_ip":
            nlp.get("destination_ip"),

        "ip_address":
            nlp.get("ip_address"),

        "protocol":
            nlp.get("protocol"),

        "port":
            nlp.get("port"),

        "username":
            nlp.get("username"),

        "timestamp":
            nlp.get("timestamp"),

        "service":
            nlp.get("service"),

        "connection_state":
            nlp.get("connection_state"),

        "recommended_actions":
            recommendations
    }