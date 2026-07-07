const http = require('http');
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ANTHROPIC_KEY = process.env.ANTHROPIC_KEY || '';
const DASHBOARD_USER = process.env.DASHBOARD_USER || 'admin';
const DASHBOARD_PASS = process.env.DASHBOARD_PASS || 'belove2024';

// ── SESIONES ───────────────────────────────────────────────
const sessions = new Map();
function crearSesion() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now());
  return token;
}
function validarSesion(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/session=([a-f0-9]+)/);
  if (!match) return false;
  const token = match[1];
  if (!sessions.has(token)) return false;
  // Sesión válida por 8 horas
  if (Date.now() - sessions.get(token) > 8 * 60 * 60 * 1000) {
    sessions.delete(token);
    return false;
  }
  return true;
}

// ── RATE LIMIT ─────────────────────────────────────────────
const rateLimits = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hora
  const maxRequests = 10;
  if (!rateLimits.has(ip)) rateLimits.set(ip, []);
  const requests = rateLimits.get(ip).filter(t => now - t < windowMs);
  requests.push(now);
  rateLimits.set(ip, requests);
  return requests.length <= maxRequests;
}

// ── LOGIN HTML ─────────────────────────────────────────────
const loginHTML = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BeLove — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{background:#f7f6f3;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:-apple-system,sans-serif;}
.card{background:#fff;border-radius:12px;padding:40px;width:100%;max-width:360px;box-shadow:0 2px 20px rgba(0,0,0,0.08);}
h1{font-size:22px;font-weight:700;margin-bottom:8px;color:#1a1a18;}
p{color:#6b6b67;font-size:14px;margin-bottom:28px;}
label{display:block;font-size:13px;font-weight:500;color:#1a1a18;margin-bottom:6px;}
input{width:100%;padding:10px 14px;border:1px solid rgba(0,0,0,0.15);border-radius:8px;font-size:14px;outline:none;margin-bottom:16px;}
input:focus{border-color:#2563eb;}
button{width:100%;padding:11px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;}
button:hover{background:#1d4ed8;}
.error{color:#dc2626;font-size:13px;margin-bottom:12px;display:none;}
</style>
</head>
<body>
<div class="card">
  <h1>🛍️ BeLove</h1>
  <p>Dashboard de resultados</p>
  <div class="error" id="err">Usuario o contraseña incorrectos</div>
  <form method="POST" action="/login">
    <label>Usuario</label>
    <input type="text" name="user" placeholder="usuario" required autofocus>
    <label>Contraseña</label>
    <input type="password" name="pass" placeholder="••••••••" required>
    <button type="submit">Entrar</button>
  </form>
</div>
</body>
</html>`;

const loginErrorHTML = loginHTML.replace('display:none', 'display:block');

// ── PARSEAR BODY FORM ──────────────────────────────────────
function parseFormBody(body) {
  const params = {};
  body.split('&').forEach(pair => {
    const [k, v] = pair.split('=');
    if (k) params[decodeURIComponent(k)] = decodeURIComponent(v || '');
  });
  return params;
}

// ── SANITIZAR TEXTO (XSS) ─────────────────────────────────
function sanitize(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

const server = http.createServer((req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

  // ── CORS ────────────────────────────────────────────────
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── LOGIN GET ────────────────────────────────────────────
  if (req.method === 'GET' && req.url === '/login') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(loginHTML);
    return;
  }

  // ── LOGIN POST ───────────────────────────────────────────
  if (req.method === 'POST' && req.url === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const { user, pass } = parseFormBody(body);
      if (user === DASHBOARD_USER && pass === DASHBOARD_PASS) {
        const token = crearSesion();
        res.writeHead(302, {
          'Set-Cookie': `session=${token}; HttpOnly; Path=/; Max-Age=28800`,
          'Location': '/'
        });
        res.end();
      } else {
        res.writeHead(401, { 'Content-Type': 'text/html' });
        res.end(loginErrorHTML);
      }
    });
    return;
  }

  // ── LOGOUT ───────────────────────────────────────────────
  if (req.url === '/logout') {
    res.writeHead(302, {
      'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0',
      'Location': '/login'
    });
    res.end();
    return;
  }

  // ── VERIFICAR SESIÓN ─────────────────────────────────────
  if (!validarSesion(req)) {
    res.writeHead(302, { 'Location': '/login' });
    res.end();
    return;
  }

  // ── PROXY CLAUDE (con rate limit) ────────────────────────
  if (req.method === 'POST' && req.url === '/api/claude') {
    if (!checkRateLimit(ip)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'Demasiadas solicitudes. Máximo 10 por hora.' } }));
      return;
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        // Sanitizar el prompt antes de enviarlo
        if (data.messages) {
          data.messages = data.messages.map(m => ({
            ...m,
            content: typeof m.content === 'string' ? m.content.substring(0, 50000) : m.content
          }));
        }
        const postData = JSON.stringify(data);

        const options = {
          hostname: 'api.anthropic.com',
          path: '/v1/messages',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': ANTHROPIC_KEY,
            'anthropic-version': '2023-06-01',
            'Content-Length': Buffer.byteLength(postData)
          },
          timeout: 120000
        };

        const apiReq = https.request(options, (apiRes) => {
          let responseData = '';
          apiRes.on('data', chunk => { responseData += chunk; });
          apiRes.on('end', () => {
            res.writeHead(apiRes.statusCode, { 'Content-Type': 'application/json' });
            res.end(responseData);
          });
        });

        apiReq.on('error', (e) => {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: e.message } }));
        });

        apiReq.on('timeout', () => {
          apiReq.destroy();
          res.writeHead(504, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'Timeout — intenta de nuevo' } }));
        });

        apiReq.write(postData);
        apiReq.end();

      } catch(e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'Invalid JSON' } }));
      }
    });
    return;
  }

  // ── SERVIR ARCHIVOS ESTÁTICOS ─────────────────────────────
  let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url);
  const ext = path.extname(filePath);
  const mimeTypes = {
    '.html': 'text/html',
    '.js':   'application/javascript',
    '.css':  'text/css',
    '.json': 'application/json',
    '.png':  'image/png',
    '.ico':  'image/x-icon',
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      fs.readFile(path.join(__dirname, 'index.html'), (err2, content2) => {
        if (err2) {
          res.writeHead(404);
          res.end('Not found');
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(content2);
        }
      });
    } else {
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
      res.end(content);
    }
  });
});

server.listen(PORT, () => {
  console.log(`✅ BeLove Dashboard corriendo en puerto ${PORT}`);
});
