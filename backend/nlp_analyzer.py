"""
AI-Powered Network Security Incident Analysis System

Module:
    NLP Security Log Analyzer

Purpose:
    Extract structured security information from security logs.

Supported extraction:
    - timestamp
    - source IP
    - destination IP
    - port
    - protocol
    - username
    - event
    - service
    - connection state
    - severity

The module uses deterministic regular expressions and
rule-based NLP.

It does NOT perform machine-learning attack classification.
The XGBoost model remains responsible for attack prediction.
"""

import re

from typing import (
    Optional,
    Dict,
    Any,
    Tuple
)


# ============================================================
# REGULAR EXPRESSIONS
# ============================================================

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\b"
)


TIMESTAMP_PATTERNS = [

    re.compile(
        r"\b\d{4}-\d{2}-\d{2}"
        r"[ T]"
        r"\d{2}:\d{2}:\d{2}\b"
    ),

    re.compile(
        r"\b\d{4}/\d{2}/\d{2}"
        r"[ T]"
        r"\d{2}:\d{2}:\d{2}\b"
    ),

]


PORT_PATTERN = re.compile(
    r"\b(?:"
    r"port"
    r"|destination\s+port"
    r"|source\s+port"
    r")"
    r"\s*[:=]?\s*"
    r"(\d{1,5})\b",
    re.IGNORECASE
)


USERNAME_PATTERNS = [

    re.compile(
        r"\busername\s*[:=]\s*"
        r"([A-Za-z0-9_.@-]+)",
        re.IGNORECASE
    ),

    re.compile(
        r"\buser\s*[:=]\s*"
        r"([A-Za-z0-9_.@-]+)",
        re.IGNORECASE
    ),

    re.compile(
        r"\bfor\s+user\s+"
        r"([A-Za-z0-9_.@-]+)",
        re.IGNORECASE
    ),

]


# ============================================================
# PROTOCOL EXTRACTION
# ============================================================
#
# Protocol extraction priority:
#
# 1. Protocol: <value>
# 2. Protocol=<value>
# 3. using <value>
# 4. Known protocol fallback
#
# This allows UNSW-NB15 values such as:
#
# TCP
# UDP
# EGP
# SCTP
# OSPF
# ARP
# etc.
#
# The explicit Protocol field always has priority.
# ============================================================


EXACT_PROTOCOL_PATTERN = re.compile(
    r"\bprotocol"
    r"\s*[:=]\s*"
    r"([A-Za-z][A-Za-z0-9_.-]*)"
    r"\b",
    re.IGNORECASE
)


USING_PROTOCOL_PATTERN = re.compile(
    r"\busing"
    r"\s+"
    r"([A-Za-z][A-Za-z0-9_.-]*)"
    r"\b",
    re.IGNORECASE
)


COMMON_PROTOCOL_PATTERN = re.compile(
    r"\b("
    r"TCP|"
    r"UDP|"
    r"ICMP|"
    r"HTTP|"
    r"HTTPS|"
    r"SSH|"
    r"FTP|"
    r"DNS|"
    r"TLS|"
    r"SCTP|"
    r"ARP|"
    r"OSPF|"
    r"GRE|"
    r"ESP|"
    r"AH|"
    r"EGP"
    r")\b",
    re.IGNORECASE
)


# ============================================================
# SERVICE
# ============================================================
#
# IMPORTANT:
#
# UNSW-NB15 uses "-" when no service is present.
#
# We preserve "-" exactly instead of converting it to None.
#
# Example:
#
# Service: -
#
# NLP result:
#
# "service": "-"
#
# ============================================================


SERVICE_PATTERN = re.compile(
    r"\bservice"
    r"\s*[:=]?\s*"
    r"([A-Za-z0-9_.:/-]+)",
    re.IGNORECASE
)


STATE_PATTERN = re.compile(
    r"\b(?:"
    r"state"
    r"|connection\s+state"
    r")"
    r"\s*[:=]?\s*"
    r"([A-Za-z0-9_-]+)",
    re.IGNORECASE
)


# ============================================================
# EVENT PATTERNS
# ============================================================

EVENT_PATTERNS = [

    (
        re.compile(
            r"failed\s+ssh\s+login|"
            r"ssh\s+login\s+failed|"
            r"failed\s+login",
            re.IGNORECASE
        ),
        "Failed SSH login"
    ),

    (
        re.compile(
            r"multiple\s+failed\s+login|"
            r"repeated\s+failed\s+login",
            re.IGNORECASE
        ),
        "Multiple failed login attempts"
    ),

    (
        re.compile(
            r"port\s+scan|"
            r"port\s+scanning|"
            r"scan\s+detected",
            re.IGNORECASE
        ),
        "Port scan detected"
    ),

    (
        re.compile(
            r"ddos|"
            r"denial\s+of\s+service|"
            r"distributed\s+denial",
            re.IGNORECASE
        ),
        "Possible denial-of-service activity"
    ),

    (
        re.compile(
            r"brute[\s-]?force|"
            r"brute\s+force\s+attack",
            re.IGNORECASE
        ),
        "Possible brute-force activity"
    ),

    (
        re.compile(
            r"malicious\s+request|"
            r"suspicious\s+http|"
            r"malformed\s+http|"
            r"sql\s+injection|"
            r"xss|"
            r"command\s+injection",
            re.IGNORECASE
        ),
        "Suspicious HTTP request"
    ),

    (
        re.compile(
            r"firewall\s+blocked|"
            r"connection\s+blocked|"
            r"blocked\s+connection",
            re.IGNORECASE
        ),
        "Blocked network connection"
    ),

    (
        re.compile(
            r"authentication\s+failure|"
            r"authentication\s+failed",
            re.IGNORECASE
        ),
        "Authentication failure"
    ),

    (
        re.compile(
            r"login\s+successful|"
            r"successful\s+login|"
            r"normal\s+login",
            re.IGNORECASE
        ),
        "Successful login"
    ),

    (
        re.compile(
            r"normal\s+http|"
            r"normal\s+request",
            re.IGNORECASE
        ),
        "Normal HTTP request"
    ),

]


# ============================================================
# SEVERITY PATTERNS
# ============================================================

CRITICAL_PATTERNS = [

    r"critical",
    r"ransomware",
    r"data\s+exfiltration",
    r"remote\s+code\s+execution",

]


HIGH_PATTERNS = [

    r"ddos",
    r"denial\s+of\s+service",
    r"brute[\s-]?force",
    r"sql\s+injection",
    r"command\s+injection",
    r"malware",

]


MEDIUM_PATTERNS = [

    r"port\s+scan",
    r"scan\s+detected",
    r"suspicious",
    r"authentication\s+failure",
    r"failed\s+login",
    r"blocked\s+connection",

]


LOW_PATTERNS = [

    r"normal",
    r"successful\s+login",
    r"routine",

]


# ============================================================
# HELPER
# ============================================================

def _clean_value(
    value: Optional[str]
) -> Optional[str]:

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    value = value.strip(
        ' .,;:"\'()[]{}'
    )

    return (
        value
        if value
        else None
    )


# ============================================================
# TIMESTAMP
# ============================================================

def _extract_timestamp(
    log: str
) -> Optional[str]:

    for pattern in TIMESTAMP_PATTERNS:

        match = pattern.search(log)

        if match:
            return match.group(0)

    return None


# ============================================================
# IP ADDRESS
# ============================================================

def _extract_ips(
    log: str
) -> Tuple[
    Optional[str],
    Optional[str]
]:

    ips = IP_PATTERN.findall(log)

    if not ips:
        return None, None

    source_ip = None
    destination_ip = None

    source_patterns = [

        r"(?:from|source|src)"
        r"\s*(?:ip)?\s*[:=]?\s*"
        r"("
        + IP_PATTERN.pattern +
        r")"

    ]

    destination_patterns = [

        r"(?:to|destination|dst|target)"
        r"\s*(?:ip)?\s*[:=]?\s*"
        r"("
        + IP_PATTERN.pattern +
        r")"

    ]

    # --------------------------------------------------------
    # SOURCE
    # --------------------------------------------------------

    for pattern_text in source_patterns:

        match = re.search(
            pattern_text,
            log,
            re.IGNORECASE
        )

        if match:

            source_ip = match.group(1)

            break

    # --------------------------------------------------------
    # DESTINATION
    # --------------------------------------------------------

    for pattern_text in destination_patterns:

        match = re.search(
            pattern_text,
            log,
            re.IGNORECASE
        )

        if match:

            destination_ip = match.group(1)

            break

    # --------------------------------------------------------
    # SINGLE IP FALLBACK
    # --------------------------------------------------------

    if (
        source_ip is None
        and
        len(ips) == 1
    ):

        source_ip = ips[0]

    # --------------------------------------------------------
    # MULTIPLE IP FALLBACK
    # --------------------------------------------------------

    if len(ips) >= 2:

        if source_ip is None:
            source_ip = ips[0]

        if destination_ip is None:
            destination_ip = ips[1]

    return (
        source_ip,
        destination_ip
    )


# ============================================================
# PORT
# ============================================================

def _extract_port(
    log: str
) -> Optional[int]:

    match = PORT_PATTERN.search(log)

    if not match:
        return None

    try:

        port = int(
            match.group(1)
        )

        if 0 <= port <= 65535:
            return port

    except ValueError:

        pass

    return None


# ============================================================
# USERNAME
# ============================================================

def _extract_username(
    log: str
) -> Optional[str]:

    for pattern in USERNAME_PATTERNS:

        match = pattern.search(log)

        if match:

            return _clean_value(
                match.group(1)
            )

    return None


# ============================================================
# PROTOCOL
# ============================================================

def _extract_protocol(
    log: str
) -> Optional[str]:

    # --------------------------------------------------------
    # PRIORITY 1
    # Exact Protocol field
    # --------------------------------------------------------

    match = EXACT_PROTOCOL_PATTERN.search(
        log
    )

    if match:

        protocol = _clean_value(
            match.group(1)
        )

        if protocol:

            return protocol.upper()

    # --------------------------------------------------------
    # PRIORITY 2
    # "using <protocol>"
    # --------------------------------------------------------

    match = USING_PROTOCOL_PATTERN.search(
        log
    )

    if match:

        protocol = _clean_value(
            match.group(1)
        )

        if protocol:

            return protocol.upper()

    # --------------------------------------------------------
    # PRIORITY 3
    # Known protocol fallback
    # --------------------------------------------------------

    match = COMMON_PROTOCOL_PATTERN.search(
        log
    )

    if match:

        protocol = _clean_value(
            match.group(1)
        )

        if protocol:

            return protocol.upper()

    return None


# ============================================================
# SERVICE
# ============================================================

def _extract_service(
    log: str
) -> Optional[str]:

    match = SERVICE_PATTERN.search(
        log
    )

    if not match:
        return None

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Do NOT convert "-" to None.
    #
    # "-" is an actual UNSW-NB15 dataset value and should
    # remain visible throughout the NLP/API/frontend pipeline.
    # --------------------------------------------------------

    service = _clean_value(
        match.group(1)
    )

    return service


# ============================================================
# CONNECTION STATE
# ============================================================

def _extract_state(
    log: str
) -> Optional[str]:

    match = STATE_PATTERN.search(
        log
    )

    if not match:
        return None

    return _clean_value(
        match.group(1)
    )


# ============================================================
# EVENT DETECTION
# ============================================================

def _detect_event(
    log: str
) -> str:

    for pattern, event_name in EVENT_PATTERNS:

        if pattern.search(log):

            return event_name

    # --------------------------------------------------------
    # Generated UNSW-NB15 network-flow logs
    # --------------------------------------------------------

    if re.search(
        r"network\s+flow|"
        r"network\s+traffic|"
        r"unsw[- ]?nb15|"
        r"network\s+record",
        log,
        re.IGNORECASE
    ):

        return "Network traffic flow"

    return "Unclassified security event"


# ============================================================
# SEVERITY DETECTION
# ============================================================

def _detect_severity(
    log: str
) -> str:

    # --------------------------------------------------------
    # CRITICAL
    # --------------------------------------------------------

    for pattern in CRITICAL_PATTERNS:

        if re.search(
            pattern,
            log,
            re.IGNORECASE
        ):

            return "CRITICAL"

    # --------------------------------------------------------
    # HIGH
    # --------------------------------------------------------

    for pattern in HIGH_PATTERNS:

        if re.search(
            pattern,
            log,
            re.IGNORECASE
        ):

            return "HIGH"

    # --------------------------------------------------------
    # MEDIUM
    # --------------------------------------------------------

    for pattern in MEDIUM_PATTERNS:

        if re.search(
            pattern,
            log,
            re.IGNORECASE
        ):

            return "MEDIUM"

    # --------------------------------------------------------
    # LOW
    # --------------------------------------------------------

    for pattern in LOW_PATTERNS:

        if re.search(
            pattern,
            log,
            re.IGNORECASE
        ):

            return "LOW"

    return "LOW"


# ============================================================
# MAIN NLP FUNCTION
# ============================================================

def analyze_security_log(
    security_log: str
) -> Dict[str, Any]:

    if security_log is None:

        raise ValueError(
            "Security log cannot be None."
        )

    if not isinstance(
        security_log,
        str
    ):

        raise TypeError(
            "Security log must be a string."
        )

    security_log = (
        security_log.strip()
    )

    if not security_log:

        raise ValueError(
            "Security log cannot be empty."
        )

    # --------------------------------------------------------
    # EXTRACTION
    # --------------------------------------------------------

    source_ip, destination_ip = (
        _extract_ips(
            security_log
        )
    )

    port = _extract_port(
        security_log
    )

    protocol = _extract_protocol(
        security_log
    )

    username = _extract_username(
        security_log
    )

    timestamp = _extract_timestamp(
        security_log
    )

    service = _extract_service(
        security_log
    )

    connection_state = _extract_state(
        security_log
    )

    event = _detect_event(
        security_log
    )

    severity = _detect_severity(
        security_log
    )

    # Preserve compatibility with existing database/frontend.
    ip_address = source_ip

    return {

        "timestamp":
            timestamp,

        "source_ip":
            source_ip,

        "destination_ip":
            destination_ip,

        "ip_address":
            ip_address,

        "port":
            port,

        "protocol":
            protocol,

        "username":
            username,

        "service":
            service,

        "connection_state":
            connection_state,

        "event":
            event,

        "severity":
            severity,

        "log_length":
            len(security_log),

        "extraction_status": {

            "timestamp":
                timestamp is not None,

            "source_ip":
                source_ip is not None,

            "destination_ip":
                destination_ip is not None,

            "port":
                port is not None,

            "protocol":
                protocol is not None,

            "username":
                username is not None,

            "service":
                service is not None,

            "connection_state":
                connection_state is not None,

            "event":
                event !=
                "Unclassified security event",

        }

    }


# ============================================================
# TESTS
# ============================================================

def _run_protocol_tests():

    print()
    print("=" * 70)
    print("PROTOCOL EXTRACTION TESTS")
    print("=" * 70)

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    tcp_log = (
        "Protocol: tcp | "
        "Service: - | "
        "State: FIN | "
        "FTP Login Flag: 0"
    )

    tcp_result = _extract_protocol(
        tcp_log
    )

    print(
        "TCP Test:",
        tcp_result
    )

    assert tcp_result == "TCP"

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    udp_log = (
        "Protocol: udp | "
        "Service: dns | "
        "State: CON"
    )

    udp_result = _extract_protocol(
        udp_log
    )

    print(
        "UDP Test:",
        udp_result
    )

    assert udp_result == "UDP"

    # --------------------------------------------------------
    # EGP
    # --------------------------------------------------------

    egp_log = (
        "Protocol: egp | "
        "Service: - | "
        "State: INT | "
        "FTP Login Flag: 0 | "
        "Ct Ftp Cmd: 0"
    )

    egp_result = _extract_protocol(
        egp_log
    )

    print(
        "EGP Test:",
        egp_result
    )

    assert egp_result == "EGP"

    # --------------------------------------------------------
    # SCTP
    # --------------------------------------------------------

    sctp_log = (
        "Protocol: sctp | "
        "Service: - | "
        "State: CON"
    )

    sctp_result = _extract_protocol(
        sctp_log
    )

    print(
        "SCTP Test:",
        sctp_result
    )

    assert sctp_result == "SCTP"

    # --------------------------------------------------------
    # OSPF
    # --------------------------------------------------------

    ospf_log = (
        "Protocol: ospf | "
        "Service: - | "
        "State: INT"
    )

    ospf_result = _extract_protocol(
        ospf_log
    )

    print(
        "OSPF Test:",
        ospf_result
    )

    assert ospf_result == "OSPF"

    # --------------------------------------------------------
    # ARP
    # --------------------------------------------------------

    arp_log = (
        "Protocol: arp | "
        "Service: - | "
        "State: INT"
    )

    arp_result = _extract_protocol(
        arp_log
    )

    print(
        "ARP Test:",
        arp_result
    )

    assert arp_result == "ARP"

    # --------------------------------------------------------
    # USING TCP
    # --------------------------------------------------------

    using_log = (
        "Failed SSH login from "
        "192.168.1.50 "
        "to 10.0.0.12 "
        "on port 22 "
        "using TCP. "
        "Username: admin."
    )

    using_result = _extract_protocol(
        using_log
    )

    print(
        "Using TCP Test:",
        using_result
    )

    assert using_result == "TCP"

    print()
    print(
        "All protocol tests passed successfully."
    )

    print("=" * 70)


# ============================================================
# SERVICE TEST
# ============================================================

def _run_service_tests():

    print()
    print("=" * 70)
    print("SERVICE EXTRACTION TESTS")
    print("=" * 70)

    # --------------------------------------------------------
    # UNSW-NB15 missing service
    # --------------------------------------------------------

    missing_service_log = (
        "Protocol: tcp | "
        "Service: - | "
        "State: FIN"
    )

    missing_service = _extract_service(
        missing_service_log
    )

    print(
        "Missing Service Test:",
        repr(missing_service)
    )

    assert missing_service == "-"

    # --------------------------------------------------------
    # Normal service
    # --------------------------------------------------------

    ftp_service_log = (
        "Protocol: tcp | "
        "Service: ftp | "
        "State: FIN"
    )

    ftp_service = _extract_service(
        ftp_service_log
    )

    print(
        "FTP Service Test:",
        repr(ftp_service)
    )

    assert ftp_service == "ftp"

    # --------------------------------------------------------
    # HTTP service
    # --------------------------------------------------------

    http_service_log = (
        "Protocol: tcp | "
        "Service: http | "
        "State: CON"
    )

    http_service = _extract_service(
        http_service_log
    )

    print(
        "HTTP Service Test:",
        repr(http_service)
    )

    assert http_service == "http"

    print()
    print(
        "All service tests passed successfully."
    )

    print("=" * 70)


# ============================================================
# FULL NLP TEST
# ============================================================

def _run_nlp_test():

    sample_log = (
        "2026-09-24 07:30:10 "
        "Failed SSH login from "
        "192.168.1.50 "
        "to 10.0.0.12 "
        "on port 22 "
        "using TCP. "
        "Username: admin. "
        "Service: ssh. "
        "State: FIN."
    )

    result = analyze_security_log(
        sample_log
    )

    print()
    print("=" * 70)
    print("NLP SECURITY LOG ANALYSIS")
    print("=" * 70)

    for key, value in result.items():

        print(
            f"{key:22}: {value}"
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    _run_protocol_tests()

    _run_service_tests()

    _run_nlp_test()