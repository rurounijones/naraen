// HTTP Sender script for ZAP, loaded by .zap/auth_hook.py. Signs every
// request to the GitHub webhook the way GitHub does, after ZAP has built or
// altered its body: X-Hub-Signature-256 is "sha256=" and the hex HMAC-SHA256
// of the exact body under the webhook secret. A signature fixed in advance
// would match only the body it was made for, and the active scan changes
// every body it sends. The secret is the public development one
// (test/testdata/devkeys/webhook.secret), which scripts/dast.sh streams in
// beside this script; the server trims surrounding whitespace, and so does
// this.
var Files = Java.type("java.nio.file.Files");
var Paths = Java.type("java.nio.file.Paths");
var JString = Java.type("java.lang.String");
var Mac = Java.type("javax.crypto.Mac");
var SecretKeySpec = Java.type("javax.crypto.spec.SecretKeySpec");
var HexFormat = Java.type("java.util.HexFormat");

var secret = new JString(Files.readAllBytes(Paths.get("/zap/wrk/webhook.secret")), "UTF-8").trim().getBytes("UTF-8");

function sendingRequest(msg, initiator, helper) {
  var path = String(msg.getRequestHeader().getURI().getPath());
  if (!path.endsWith("/webhooks/github")) {
    return;
  }
  var mac = Mac.getInstance("HmacSHA256");
  mac.init(new SecretKeySpec(secret, "HmacSHA256"));
  var sum = mac.doFinal(msg.getRequestBody().getBytes());
  msg.getRequestHeader().setHeader("X-Hub-Signature-256", "sha256=" + HexFormat.of().formatHex(sum));
}

function responseReceived(msg, initiator, helper) {}
