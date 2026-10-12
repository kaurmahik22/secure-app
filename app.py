"""Secure Cloud Web App - lab sample.

Security features demonstrated:
  * No hard-coded secrets: config comes from environment variables
  * AWS access via the instance's IAM role (boto3 default credential chain)
  * HTTPS enforcement (redirect + HSTS) when running behind an ALB
  * Security response headers
"""
import os

from flask import Flask, jsonify, redirect, render_template_string, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# The ALB terminates TLS and forwards X-Forwarded-Proto / X-Forwarded-For.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ---- Secrets / config come from the environment, never from source code ----
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY")  # None if unset
ENFORCE_HTTPS = os.environ.get("ENFORCE_HTTPS", "true").lower() == "true"
SHOW_IDENTITY = os.environ.get("SHOW_IDENTITY", "false").lower() == "true"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


@app.before_request
def force_https():
    # /health is exempt: ALB health checks are plain HTTP to the instance.
    if ENFORCE_HTTPS and not request.is_secure and request.path != "/health":
        return redirect(request.url.replace("http://", "https://", 1), code=301)


@app.after_request
def security_headers(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
    return resp


def iam_identity():
    """Ask AWS STS who we are. Works only if an IAM role is attached."""
    try:
        import boto3
        from botocore.config import Config

        sts = boto3.client("sts", region_name=AWS_REGION,
                           config=Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1}))
        arn = sts.get_caller_identity()["Arn"]
        return arn if SHOW_IDENTITY else "IAM role detected (ARN hidden)"
    except Exception:
        return "No IAM role / credentials available"


def checks():
    return {
        "https_request": request.is_secure,
        "secret_loaded_from_env": bool(app.config["SECRET_KEY"]),
        "https_enforced": ENFORCE_HTTPS,
        "iam_identity": iam_identity(),
        "client_ip": request.remote_addr,
    }


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Secure Cloud App</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;max-width:640px;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
 h1{margin-bottom:.2rem} .sub{color:#666;margin-top:0}
 table{width:100%;border-collapse:collapse;margin-top:1.5rem}
 td{padding:.6rem;border-bottom:1px solid #ddd} td:first-child{font-weight:600}
 .ok{color:#0a7d33}.bad{color:#b00020}
</style></head><body>
<h1>Secure Cloud App</h1><p class="sub">Cloud security lab &mdash; deployment status</p>
<table>
{% for label, key, good in rows %}
<tr><td>{{ label }}</td>
<td class="{{ 'ok' if good else 'bad' }}">{{ c[key] if c[key] is not boolean else ('Yes' if c[key] else 'No') }}</td></tr>
{% endfor %}
</table></body></html>"""


@app.route("/")
def index():
    c = checks()
    rows = [
        ("Connection is HTTPS", "https_request", c["https_request"]),
        ("Secret loaded from environment", "secret_loaded_from_env", c["secret_loaded_from_env"]),
        ("HTTPS enforcement enabled", "https_enforced", c["https_enforced"]),
        ("AWS identity", "iam_identity", c["iam_identity"].startswith("IAM") or c["iam_identity"].startswith("arn")),
    ]
    return render_template_string(PAGE, c=c, rows=rows)


@app.route("/status")
def status():
    return jsonify(checks())


@app.route("/health")
def health():
    return "ok", 200


if __name__ == "__main__":
    # Local dev only. In AWS, gunicorn runs the app (see Procfile / Dockerfile).
    app.run(host="127.0.0.1", port=8000)
