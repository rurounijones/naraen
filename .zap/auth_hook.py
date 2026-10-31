# Hook for zap-api-scan.py (--hook). Sends the development token that
# scripts/dast.sh puts in NARAEN_DAST_TOKEN as the Authorization header of
# every request, through ZAP's replacer. ZAP's own ZAP_AUTH_HEADER_VALUE does
# not reach the requests the API scan builds from the OpenAPI spec; a replacer
# rule added before the import does.
import os


def zap_started(zap, target):
    token = os.environ.get("NARAEN_DAST_TOKEN")
    if token:
        zap.replacer.add_rule(description="dev token", enabled=True, matchtype="REQ_HEADER",
                              matchregex=False, matchstring="Authorization", replacement=token)
