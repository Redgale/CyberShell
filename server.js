/**
 * CyberShell — Web SSH Gateway
 * Node.js backend: HTTPS + WebSocket (WSS) + SSH2
 */

'use strict';

const express  = require('express');
const https    = require('https');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const os       = require('os');
const { execSync } = require('child_process');

// ─── Configuration ─────────────────────────────────────────────────────────

const PORT         = parseInt(process.env.PORT || '2222', 10);
const CERT_DIR     = path.join(__dirname, 'certs');
const KEY_FILE     = path.join(CERT_DIR, 'server.key');
const CERT_FILE    = path.join(CERT_DIR, 'server.cert');
const RATE_MAX     = 10;           // max SSH connection attempts
const RATE_WINDOW  = 60_000;       // per 60 seconds
const SSH_TIMEOUT  = 15_000;       // SSH handshake timeout (ms)
const KEEPALIVE_MS = 30_000;       // SSH keepalive interval

// ─── TLS Certificate ────────────────────────────────────────────────────────

function ensureCertificate() {
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

  if (!fs.existsSync(KEY_FILE) || !fs.existsSync(CERT_FILE)) {
    console.log('[TLS] Generating self-signed certificate (4096-bit RSA, valid 10 years)…');
    try {
      execSync(
        `openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes ` +
        `-keyout "${KEY_FILE}" -out "${CERT_FILE}" ` +
        `-subj "/CN=cybershell.local/O=CyberShell/OU=SSH Gateway" ` +
        `-addext "subjectAltName=IP:127.0.0.1,IP:::1,DNS:localhost,DNS:cybershell.local"`,
        { stdio: 'pipe' }
      );
      fs.chmodSync(KEY_FILE, 0o600);
      console.log('[TLS] Certificate written to ./certs/');
    } catch (err) {
      console.error('[TLS] openssl failed — install openssl or supply certs manually:\n', err.message);
      process.exit(1);
    }
  }

  return {
    key:  fs.readFileSync(KEY_FILE),
    cert: fs.readFileSync(CERT_FILE),
  };
}

// ─── Express App ────────────────────────────────────────────────────────────

const app = express();

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// Serve xterm from local npm packages (no CDN dependency)
app.use('/xterm',           express.static(path.join(__dirname, 'node_modules/@xterm/xterm')));
app.use('/xterm-addon-fit', express.static(path.join(__dirname, 'node_modules/@xterm/addon-fit')));

// Security headers
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ─── HTTPS Server ───────────────────────────────────────────────────────────

const tlsOpts = ensureCertificate();
const httpsServer = https.createServer(tlsOpts, app);

// ─── WebSocket Server ────────────────────────────────────────────────────────

const wss = new WebSocket.Server({ server: httpsServer });

// ─── Rate Limiting ───────────────────────────────────────────────────────────

/** @type {Map<string, {count: number, windowStart: number}>} */
const rateLimitStore = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  let rec = rateLimitStore.get(ip);

  if (!rec || now - rec.windowStart > RATE_WINDOW) {
    rec = { count: 0, windowStart: now };
  }

  rec.count++;
  rateLimitStore.set(ip, rec);
  return rec.count > RATE_MAX;
}

// Prune stale entries every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW * 2;
  for (const [ip, rec] of rateLimitStore) {
    if (rec.windowStart < cutoff) rateLimitStore.delete(ip);
  }
}, 5 * 60_000);

// ─── WebSocket → SSH Bridge ──────────────────────────────────────────────────

wss.on('connection', (ws, req) => {
  const clientIP = (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket.remoteAddress
  );

  let sshConn    = null;
  let shellStream = null;
  let connected  = false;

  // Helper: safe send to browser
  const send = (obj) => {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify(obj)); } catch {}
    }
  };

  // Full cleanup — called on any disconnect or error
  const cleanup = () => {
    connected = false;
    if (shellStream) {
      try { shellStream.end(); } catch {}
      shellStream = null;
    }
    if (sshConn) {
      try { sshConn.end(); } catch {}
      sshConn = null;
    }
  };

  ws.on('message', (rawData) => {
    let msg;
    try { msg = JSON.parse(rawData.toString()); }
    catch { return; }

    switch (msg.type) {

      // ── CONNECT ──────────────────────────────────────────────────────────
      case 'connect': {
        if (connected) {
          send({ type: 'error', message: 'Already connected. Disconnect first.' });
          return;
        }

        // Rate limit check
        if (isRateLimited(clientIP)) {
          send({ type: 'error', message: 'Too many connection attempts. Wait 60 seconds.' });
          return;
        }

        const { host, port = 22, username, password, rows = 24, cols = 80 } = msg;

        // Input validation
        if (!host || !username || !password) {
          send({ type: 'error', message: 'Host, username, and password are required.' });
          return;
        }
        if (!/^[\w.\-[\]:]+$/.test(host)) {
          send({ type: 'error', message: 'Invalid host address.' });
          return;
        }
        if (!/^[\w.\-@+]+$/.test(username)) {
          send({ type: 'error', message: 'Invalid username.' });
          return;
        }
        const sshPort = parseInt(port, 10);
        if (isNaN(sshPort) || sshPort < 1 || sshPort > 65535) {
          send({ type: 'error', message: 'Invalid port number.' });
          return;
        }

        sshConn = new Client();

        sshConn.on('ready', () => {
          sshConn.shell(
            {
              term: 'xterm-256color',
              rows: Math.max(1, parseInt(rows, 10) || 24),
              cols: Math.max(1, parseInt(cols, 10) || 80),
            },
            (err, stream) => {
              if (err) {
                send({ type: 'error', message: `Shell error: ${err.message}` });
                cleanup();
                return;
              }

              shellStream = stream;
              connected   = true;

              send({ type: 'connected', sessionId: crypto.randomBytes(8).toString('hex') });

              // SSH → browser
              stream.on('data', (chunk) => {
                send({ type: 'data', data: chunk.toString('base64') });
              });
              stream.stderr?.on('data', (chunk) => {
                send({ type: 'data', data: Buffer.from(chunk).toString('base64') });
              });

              stream.on('close', () => {
                send({ type: 'disconnected', message: 'Remote session closed.' });
                cleanup();
              });
            }
          );
        });

        sshConn.on('error', (err) => {
          send({ type: 'error', message: `SSH: ${err.message}` });
          cleanup();
        });

        // Support keyboard-interactive auth (sudo prompts etc.)
        sshConn.on('keyboard-interactive', (_name, _instr, _lang, prompts, finish) => {
          finish(prompts.map(() => password));
        });

        send({ type: 'status', message: `Connecting to ${username}@${host}:${sshPort}…` });

        try {
          sshConn.connect({
            host,
            port:     sshPort,
            username,
            password,
            tryKeyboard:      true,
            readyTimeout:     SSH_TIMEOUT,
            keepaliveInterval: KEEPALIVE_MS,
          });
        } catch (err) {
          send({ type: 'error', message: `Init error: ${err.message}` });
          cleanup();
        }
        break;
      }

      // ── STDIN → SSH ───────────────────────────────────────────────────────
      case 'data': {
        if (shellStream && connected) {
          try { shellStream.write(msg.data); }
          catch { send({ type: 'error', message: 'Write failed.' }); }
        }
        break;
      }

      // ── TERMINAL RESIZE ──────────────────────────────────────────────────
      case 'resize': {
        if (shellStream && connected) {
          const r = Math.max(1, parseInt(msg.rows, 10) || 24);
          const c = Math.max(1, parseInt(msg.cols, 10) || 80);
          try { shellStream.setWindow(r, c, 0, 0); } catch {}
        }
        break;
      }

      // ── CLIENT-INITIATED DISCONNECT ───────────────────────────────────────
      case 'disconnect': {
        send({ type: 'disconnected', message: 'Disconnected.' });
        cleanup();
        break;
      }

      // ── KEEPALIVE ─────────────────────────────────────────────────────────
      case 'ping': {
        send({ type: 'pong' });
        break;
      }
    }
  });

  ws.on('close',   cleanup);
  ws.on('error', () => cleanup());
});

// ─── Start ──────────────────────────────────────────────────────────────────

httpsServer.listen(PORT, '0.0.0.0', () => {
  const ifaces = os.networkInterfaces();
  const networkIPs = [];

  for (const list of Object.values(ifaces)) {
    for (const addr of list) {
      if (addr.family === 'IPv4' && !addr.internal) networkIPs.push(addr.address);
    }
  }

  const red    = '\x1b[31m';
  const yellow = '\x1b[33m';
  const dim    = '\x1b[90m';
  const reset  = '\x1b[0m';
  const bold   = '\x1b[1m';

  console.log(`\n${red}${bold}`);
  console.log('  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     ');
  console.log('  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██║     ██║     ');
  console.log('  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║█████╗  ██║     ██║     ');
  console.log('  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██╔══╝  ██║     ██║     ');
  console.log('  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║███████╗███████╗███████╗');
  console.log(`   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝${reset}`);
  console.log(`${red}  ─────────────────── WEB SSH GATEWAY ───────────────────${reset}\n`);
  console.log(`${yellow}  ► Local    ${reset}https://localhost:${PORT}`);
  networkIPs.forEach(ip => {
    console.log(`${yellow}  ► Network  ${reset}https://${ip}:${PORT}`);
  });
  console.log(`\n${dim}  Accept the self-signed certificate warning in your browser.`);
  console.log(`  To trust it permanently: import ./certs/server.cert into your OS/browser.${reset}\n`);
});
