# CyberShell — Web SSH Gateway

A self-hosted, browser-based SSH client for your local network. Runs as a Node.js HTTPS web service; connect to any SSH host on your LAN from any browser on the same network.

```
┌──────────────────────────────────────────────────────────┐
│  Browser (any device on WiFi)                            │
│  https://192.168.1.5:2222  ──►  CyberShell Server       │
│                                      │ WSS + SSH2        │
│                                      ▼                   │
│                               Headless Pi / NAS / etc.   │
└──────────────────────────────────────────────────────────┘
```

---

## Requirements

- **Node.js** 18+ (`node --version`)
- **openssl** (pre-installed on macOS/Linux; on Windows use WSL or Git Bash)
- Any modern browser (Chrome, Firefox, Edge, Safari)

---

## Setup

```bash
# 1. Install dependencies (already done if you see node_modules/)
npm install

# 2. Start the server
npm start
```

On first run, CyberShell auto-generates a **self-signed TLS certificate** in `./certs/`.

---

## Accessing the UI

The server prints its URLs on startup:

```
► Local    https://localhost:2222
► Network  https://192.168.1.5:2222   ← use this from other devices
```

Open the Network URL from any device on the same WiFi.

### Browser Certificate Warning

Because the certificate is self-signed, your browser will warn you. This is expected.

| Browser | What to click |
|---------|--------------|
| Chrome  | Advanced → Proceed to … (unsafe) |
| Firefox | Advanced… → Accept the Risk and Continue |
| Safari  | Show Details → visit this website |
| Edge    | Advanced → Continue to … (unsafe) |

**To permanently trust** (recommended for regular use):

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/server.cert

# Linux (Debian/Ubuntu)
sudo cp certs/server.cert /usr/local/share/ca-certificates/cybershell.crt && sudo update-ca-certificates
```

---

## Usage

1. Enter your target in the form: `user@host` (e.g. `root@192.168.1.12` or `pi@raspberrypi.local`)
2. Change the port if needed (default: 22)
3. Enter the SSH password
4. Press **ESTABLISH CONNECTION** or hit Enter

The full terminal opens in your browser. All standard terminal shortcuts work (Ctrl+C, Ctrl+D, arrow keys, tab completion, etc.).

---

## Security Model

| Feature | Detail |
|---------|--------|
| Transport | HTTPS + WSS (TLS 1.2/1.3) — traffic is encrypted end-to-end |
| Credentials | Password sent only over encrypted WebSocket; **never logged or stored** |
| Cert | Self-signed RSA-4096, SHA-256, 10-year validity |
| Rate limiting | Max 10 SSH connection attempts per IP per 60 seconds |
| Input validation | Host and username sanitized server-side |
| Session isolation | Each WebSocket gets an independent SSH connection |

> **Note:** This is designed for trusted local networks. Do not expose port 2222 to the public internet without additional hardening (firewall rules, VPN, reverse proxy with auth, etc.).

---

## Configuration

Override defaults with environment variables:

```bash
PORT=8443 npm start     # change the HTTPS port
```

To use your **own TLS certificate** (e.g. from Let's Encrypt):

```bash
cp /path/to/privkey.pem   certs/server.key
cp /path/to/fullchain.pem certs/server.cert
npm start
```

---

## Troubleshooting

**"Connection refused" / can't reach the URL**
- Make sure the server is running (`npm start`)
- Check firewall: `sudo ufw allow 2222/tcp` (Linux) or allow Node.js in Windows Firewall

**"SSH: Authentication failed"**
- Double-check username and password
- Ensure the target host has SSH running: `systemctl status ssh`

**Terminal renders blank after connect**
- Hard-refresh the browser (Ctrl+Shift+R)
- Check browser console for errors

**Certificate error that won't dismiss**
- Navigate directly to `https://YOUR-IP:2222`, accept the cert there, then try again

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Server | Node.js + Express |
| SSH    | ssh2 (pure-JS SSH2 client) |
| WebSocket | ws |
| TLS   | Node.js built-in https + openssl |
| Terminal | xterm.js (served locally) |
| Theme | Custom CSS — Cyberpunk red |
