from dataclasses import dataclass

ROLE_DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
ROLE_DATABASE          = "DATABASE"
ROLE_WEB_SERVER        = "WEB_SERVER"
ROLE_SSH_SERVER        = "SSH_SERVER"
ROLE_DNS_SERVER        = "DNS_SERVER"
ROLE_INTERNAL          = "INTERNAL"

CRITICALITY_SCORES = {
    ROLE_DOMAIN_CONTROLLER: 10,
    ROLE_DATABASE:           9,
    ROLE_SSH_SERVER:         7,
    ROLE_WEB_SERVER:         6,
    ROLE_DNS_SERVER:         5,
    ROLE_INTERNAL:           3,
}

PORT_ROLE_MAP = {
    88:    ROLE_DOMAIN_CONTROLLER,
    389:   ROLE_DOMAIN_CONTROLLER,
    636:   ROLE_DOMAIN_CONTROLLER,
    3268:  ROLE_DOMAIN_CONTROLLER,
    3306:  ROLE_DATABASE,
    5432:  ROLE_DATABASE,
    1433:  ROLE_DATABASE,
    27017: ROLE_DATABASE,
    6379:  ROLE_DATABASE,
    80:    ROLE_WEB_SERVER,
    443:   ROLE_WEB_SERVER,
    8080:  ROLE_WEB_SERVER,
    8443:  ROLE_WEB_SERVER,
    22:    ROLE_SSH_SERVER,
    53:    ROLE_DNS_SERVER,
}

ROLE_PRIORITY = [
    ROLE_DOMAIN_CONTROLLER,
    ROLE_DATABASE,
    ROLE_SSH_SERVER,
    ROLE_WEB_SERVER,
    ROLE_DNS_SERVER,
    ROLE_INTERNAL,
]


def classify_host(ports: list[int]) -> tuple[str, int]:
    """
    Given a list of open ports on a host, return (role, criticality_score).
    Highest priority role wins if multiple match.
    """
    detected_roles = set()
    for port in ports:
        if port in PORT_ROLE_MAP:
            detected_roles.add(PORT_ROLE_MAP[port])

    for role in ROLE_PRIORITY:
        if role in detected_roles:
            return role, CRITICALITY_SCORES[role]

    return ROLE_INTERNAL, CRITICALITY_SCORES[ROLE_INTERNAL]
