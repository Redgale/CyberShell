/**
 * CyberShell — Web SSH Gateway
 * Node.js backend: HTTPS + WebSocket (WSS) + SSH2
 */

'use strict';

const express   = require('express');
const http     = require('http');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const mDNS      = require('multicast-dns');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const os        = require('os');
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

// ─── mDNS Helpers ────────────────────────────────────────────────────────────

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

/** True when the host should be resolved via mDNS rather than system DNS */
function needsMdns(host) {
  if (IPV4_RE.test(host)) return false;      // plain IPv4 — skip
  if (host.includes(':'))  return false;      // IPv6     — skip
  if (host.endsWith('.local')) return true;   // foo.local
  if (!host.includes('.'))     return true;   // bare name, e.g. "pi"
  return false;
}

/**
 * Resolve a hostname to IPv4 via mDNS (multicast DNS, RFC 6762).
 * Bare names are automatically suffixed with ".local".
 */
function resolveMdns(hostname, timeoutMs = 5000) {
  const fullName = hostname.endsWith('.local')
    ? hostname
    : `${hostname}.local`;

  return new Promise((resolve, reject) => {
    const m = mDNS();
    let done = false;

    const finish = (err, ip) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { m.destroy(); } catch {}
      err ? reject(err) : resolve(ip);
    };

    const timer = setTimeout(
      () => finish(new Error(`mDNS: "${fullName}" not found (timeout ${timeoutMs / 1000}s)`)),
      timeoutMs
    );

    m.on('response', ({ answers = [], additionals = [] }) => {
      const aRec = [...answers, ...additionals]
        .find(r => r.type === 'A' && r.name === fullName);
      if (aRec) finish(null, aRec.data);
    });

    m.on('error', (err) => finish(err));

    m.query({ questions: [{ name: fullName, type: 'A' }] });
  });
}

/**
 * Discover LAN devices that expose SSH, using mDNS service browsing.
 * Probes _ssh._tcp.local and _sftp-ssh._tcp.local PTR records, and
 * passively collects any .local A records seen in responses/additionals.
 */
function discoverDevices(timeoutMs = 3500) {
  return new Promise((resolve) => {
    const m = mDNS();
    // hostname → { hostname, ip, port, label }
    const seen = new Map();

    const upsert = (hostname, ip, port, label) => {
      if (!hostname) return;
      const prev = seen.get(hostname) || {};
      seen.set(hostname, {
        hostname,
        ip:    ip    || prev.ip,
        port:  port  || prev.port  || 22,
        label: label || prev.label || hostname.replace(/\.local$/, ''),
      });
    };

    m.on('response', ({ answers = [], additionals = [] }) => {
      const all = [...answers, ...additionals];

      // Index all A records by name for quick lookup
      const aByName = {};
      for (const r of all) {
        if (r.type === 'A') aByName[r.name] = r.data;
      }

      // Walk PTR → SRV → A chains (devices that advertise SSH via DNS-SD)
      for (const ptr of all.filter(r => r.type === 'PTR')) {
        if (!ptr.name.endsWith('._tcp.local')) continue;
        const svcInstance = ptr.data;                          // e.g. "pi@raspberrypi._ssh._tcp.local"
        const srv = all.find(r => r.type === 'SRV' && r.name === svcInstance);
        if (srv) {
          const target = srv.data.target;                      // e.g. "raspberrypi.local"
          const ip = aByName[target];
          const label = svcInstance
            .replace(/\._ssh\._tcp\.local$/,      '')
            .replace(/\._sftp-ssh\._tcp\.local$/, '');
          upsert(target, ip, srv.data.port, label);
        }
      }

      // Passively collect any .local A records (devices that DON'T use DNS-SD
      // but whose traffic we happen to see during the scan window)
      for (const [name, ip] of Object.entries(aByName)) {
        if (name.endsWith('.local')) upsert(name, ip, 22, null);
      }
    });

    m.on('error', () => {});   // non-fatal during discovery

    // Probe SSH service records; other mDNS traffic fills in the rest
    m.query({
      questions: [
        { name: '_ssh._tcp.local',      type: 'PTR' },
        { name: '_sftp-ssh._tcp.local', type: 'PTR' },
      ],
    });

    setTimeout(() => {
      try { m.destroy(); } catch {}
      const results = [...seen.values()]
        .filter(d => d.ip)                               // must have a resolved IP
        .sort((a, b) => a.label.localeCompare(b.label));
      resolve(results);
    }, timeoutMs);
  });
}

// ─── REST: device discovery ───────────────────────────────────────────────────

app.get('/api/discover', async (_req, res) => {
  try {
    const devices = await discoverDevices();
    res.json({ ok: true, devices });
  } catch (err) {
    res.json({ ok: false, devices: [], error: err.message });
  }
});



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

        // Async IIFE — needed so we can await mDNS resolution before SSH
        (async () => {
          // ── mDNS resolution ──────────────────────────────────────────────
          let resolvedHost = host;
          if (needsMdns(host)) {
            const label = host.endsWith('.local') ? host : `${host}.local`;
            send({ type: 'mdns_resolving', hostname: label });
            try {
              resolvedHost = await resolveMdns(host);
              send({ type: 'mdns_resolved', hostname: label, ip: resolvedHost });
            } catch (err) {
              send({ type: 'error', message: err.message });
              return;
            }
          }

          // ── SSH connection ───────────────────────────────────────────────
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

          // Support keyboard-interactive auth (sudo prompts, etc.)
          sshConn.on('keyboard-interactive', (_name, _instr, _lang, prompts, finish) => {
            finish(prompts.map(() => password));
          });

          send({ type: 'status', message: `Connecting to ${username}@${resolvedHost}:${sshPort}…` });

          try {
            sshConn.connect({
              host:              resolvedHost,
              port:              sshPort,
              username,
              password,
              tryKeyboard:       true,
              readyTimeout:      SSH_TIMEOUT,
              keepaliveInterval: KEEPALIVE_MS,
            });
          } catch (err) {
            send({ type: 'error', message: `Init error: ${err.message}` });
            cleanup();
          }
        })();

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
