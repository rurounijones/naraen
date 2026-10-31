# Hook for zap-api-scan.py (--hook). Gives each authenticated endpoint the
# credential it takes, through URL-scoped rules in ZAP's replacer, from tokens
# scripts/dast.sh puts in the environment:
#
#   NARAEN_DAST_TOKEN       a writer LFS token, for the Batch API
#   NARAEN_DAST_OIDC_TOKEN  an OIDC token from the dev issuer, for the CI
#                           token exchange
#
# ZAP's own ZAP_AUTH_HEADER_VALUE does not reach the requests the API scan
# builds from the OpenAPI spec; replacer rules added before the import do.
import os

RULES = [
    ("dev LFS token", "NARAEN_DAST_TOKEN", ".*/objects/batch.*"),
    ("dev OIDC token", "NARAEN_DAST_OIDC_TOKEN", ".*/ci/token.*"),
]


def zap_started(zap, target):
    for description, var, url in RULES:
        token = os.environ.get(var)
        if token:
            zap.replacer.add_rule(description=description, enabled=True, matchtype="REQ_HEADER",
                                  matchregex=False, matchstring="Authorization", replacement=token, url=url)
