// /opt/foundation-shield/scripts/honey-listener.js
// Runs on a non-registered port (7474) as a honeypot.
// Logs any connection attempt to /var/log/fo-sys/honey-hits.log
'use strict';
const http = require('http');
const fs   = require('fs');

const PORT     = parseInt(process.env.HONEY_PORT || '7474');
const LOG_FILE = '/var/log/fo-sys/honey-hits.log';

const HONEY_CREDS = {
  api_key:       'sk-HONEY-DECOY-NOT-REAL-KEY-0000000000000000000000000000000000000000',
  db_url:        'postgresql://admin:HONEY_PASSWORD_DECOY@localhost:5432/production',
  telegram_token: '0000000000:HONEYDECOY_TOKEN_NOTREAL_AAAAAAAAAAAAA',
};

function logHit(ip, path, method, body, credential) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), ip, path, method, body: body?.slice(0, 200), credential }) + '\n';
  try { fs.appendFileSync(LOG_FILE, entry); } catch (_) {}
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', d => body += d.toString().slice(0, 500));
  req.on('end', () => {
    const ip = req.socket.remoteAddress;
    let credential = null;
    for (const [name, value] of Object.entries(HONEY_CREDS)) {
      if (body.includes(value) || (req.headers.authorization || '').includes(value)) {
        credential = name;
        break;
      }
    }
    logHit(ip, req.url, req.method, body, credential);
    setTimeout(() => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
    }, 2000);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[honey-listener] Decoy HTTP listener on :${PORT}`);
});

server.on('error', err => console.error('[honey-listener] error:', err.message));
