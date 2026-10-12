# Secure Cloud App – AWS Deployment Guide

Architecture: **Internet → ALB (80 redirect, 443 + ACM cert) → EC2 (port 8000, gunicorn + Flask)**

ACM certificates cannot be installed directly on EC2, so the ALB terminates TLS. You need a
domain name you control (Route 53 or any registrar) to get a validated ACM certificate.

## 1. Test locally
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export APP_SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
export ENFORCE_HTTPS=false        # local only
python app.py                     # http://127.0.0.1:8000  and /status
```

## 2. IAM role (no hard-coded credentials)
IAM → Roles → Create role → EC2 → attach **AmazonSSMManagedInstanceCore** (lets you use
Session Manager, so you never open SSH). Name it `secure-app-role`. Screenshot the role's permissions.

## 3. Security groups
**alb-sg** (inbound): HTTP 80 and HTTPS 443 from 0.0.0.0/0. 
**app-sg** (inbound): Custom TCP **8000 from alb-sg only**. No SSH, no other rules.
Screenshot both inbound rule tables.

## 4. Launch EC2
Amazon Linux 2023, t2/t3.micro, public subnet, auto-assign public IP, attach `secure-app-role` and `app-sg`.
Connect via **Session Manager**, then:
```bash
sudo dnf install -y python3-pip git
# copy project to the instance (git clone your repo, or paste files) into /opt/app
cd /opt/app && sudo pip3 install -r requirements.txt
```
Create `/etc/secure-app.env` (root-owned, `chmod 600`):
```
APP_SECRET_KEY=<paste a random 64-char hex string>
ENFORCE_HTTPS=true
AWS_REGION=us-east-1
```
Create `/etc/systemd/system/secure-app.service`:
```
[Unit]
Description=Secure Flask App
After=network.target
[Service]
WorkingDirectory=/opt/app
EnvironmentFile=/etc/secure-app.env
ExecStart=/usr/local/bin/gunicorn --bind 0.0.0.0:8000 app:app
Restart=always
[Install]
WantedBy=multi-user.target
```
`sudo systemctl daemon-reload && sudo systemctl enable --now secure-app`

## 5. Certificate + load balancer
1. **ACM** → Request public certificate → your domain (e.g. `app.example.com`) → DNS validation → wait for "Issued". Screenshot.
2. **EC2 → Target Groups**: HTTP:8000, health check path `/health`, register your instance.
3. **EC2 → Load Balancers → Create ALB** (internet-facing, 2 public subnets, `alb-sg`).
   - Listener **HTTP:80 → Redirect to HTTPS:443** (301)
   - Listener **HTTPS:443 → forward to target group**, select the ACM cert, security policy `ELBSecurityPolicy-TLS13-1-2-2021-06` (or similar TLS 1.2+)
4. DNS: CNAME/alias `app.example.com` → ALB DNS name.

## 6. Test (take screenshots/output)
```bash
curl -I http://app.example.com          # expect 301 → https://
curl -I https://app.example.com         # expect 200 + Strict-Transport-Security header
curl https://app.example.com/status     # secret_loaded_from_env: true, IAM role detected
openssl s_client -connect app.example.com:443 -tls1_1   # should fail (old TLS rejected)
nmap -Pn -p 22,80,443,8000 app.example.com               # only 80 and 443 open on the ALB
nmap -Pn -p 22,8000 <EC2-public-IP>                      # filtered/closed (SG blocks it)
grep -rniE "(secret|password|AKIA)" app.py               # no hard-coded secrets
```
Optional: set `SHOW_IDENTITY=true` temporarily to screenshot the role ARN, then turn it off.

## 7. Dependency scan (pick one)
```bash
pip install pip-audit && pip-audit -r requirements.txt          # simplest
# or Snyk:   npm i -g snyk && snyk auth && snyk test --file=requirements.txt
# or OWASP Dependency-Check: dependency-check.sh --scan . --format HTML
# or Amazon Inspector / ECR scan if you push the Docker image
```
Pick one finding and document: package + version, CVE ID, severity, what an attacker could do,
and the fix version. Then update `requirements.txt` to the fixed versions
(e.g. `Werkzeug>=3.0.3`, `gunicorn>=22.0.0`), re-run the scan, and screenshot the clean result.

## 8. Write-up checklist (200–300 words)
Explain how the layers combine: TLS (ACM + ALB redirect + HSTS) protects data in transit;
security groups limit exposure to 80/443 (and keep the instance reachable only via the ALB);
the IAM role removes long-lived credentials; env vars keep secrets out of source control;
dependency scanning reduces supply-chain risk. Mention that each control covers a failure of the others.

## Clean up (avoid charges)
Delete the ALB, target group, EC2 instance, and (optionally) the ACM cert/DNS record when done.
