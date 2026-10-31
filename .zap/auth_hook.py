# Hook for zap-api-scan.py (--hook). Gives each authenticated endpoint the
# credential it takes, from what scripts/dast.sh provides:
#
#   NARAEN_DAST_TOKEN       a writer LFS token, for the Batch API
#   NARAEN_DAST_OIDC_TOKEN  an OIDC token from the dev issuer, for the CI
#                           token exchange
#   sign_webhook.js         signs each GitHub webhook delivery with the dev
#                           webhook secret, streamed in beside it
#
# The tokens go in through URL-scoped rules in ZAP's replacer. ZAP's own
# ZAP_AUTH_HEADER_VALUE does not reach the requests the API scan builds from
# the OpenAPI spec; replacer rules added before the import do. A webhook
# signature depends on each body, so a fixed replacement cannot carry it; an
# HTTP Sender script computes it as every request is sent.
import os

RULES = [
    ("dev LFS token", "NARAEN_DAST_TOKEN", ".*/objects/batch.*"),
    ("dev OIDC token", "NARAEN_DAST_OIDC_TOKEN", ".*/ci/token.*"),
]
SIGNER = "/zap/wrk/sign_webhook.js"


def zap_started(zap, target):
    for description, var, url in RULES:
        token = os.environ.get(var)
        if token:
            zap.replacer.add_rule(description=description, enabled=True, matchtype="REQ_HEADER",
                                  matchregex=False, matchstring="Authorization", replacement=token, url=url)
    if os.path.exists(SIGNER):
        engines = [e for e in zap.script.list_engines if "graal" in e.lower()]
        if not engines:
            raise RuntimeError("no Graal.js script engine in ZAP: %s" % zap.script.list_engines)
        result = zap.script.load("sign-webhook", "httpsender", engines[0], SIGNER)
        if result != "OK":
            raise RuntimeError("loading %s: %s" % (SIGNER, result))
        zap.script.enable("sign-webhook")
