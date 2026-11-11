import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = '0.0.0.0';

// MIME type dictionary
const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.mjs': 'application/javascript; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.xml': 'application/xml; charset=UTF-8',
  '.txt': 'text/plain; charset=UTF-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf'
};

// Rate limiting map (IP -> { count, resetTime })
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 120; // 120 req / min

function isRateLimited(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };
  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + RATE_LIMIT_WINDOW_MS;
  } else {
    record.count++;
  }
  rateLimitMap.set(ip, record);
  return record.count > MAX_REQUESTS_PER_WINDOW;
}

// Clean up stale rate limits every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) rateLimitMap.delete(ip);
  }
}, 5 * 60 * 1000);

// Default Security Headers
function setSecurityHeaders(res, isHtml = false) {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  if (isHtml) {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com https://fonts.gstatic.com https://www.googletagmanager.com https://www.google-analytics.com data: blob:; " +
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://www.googletagmanager.com https://www.google-analytics.com; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com data:; " +
      "img-src 'self' data: blob: https:; " +
      "connect-src 'self' https://www.google-analytics.com https://analytics.google.com https://unpkg.com;"
    );
  }
}

const server = http.createServer((req, res) => {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';

  if (isRateLimited(clientIp)) {
    setSecurityHeaders(res);
    res.writeHead(429, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Too many requests. Please slow down.' }));
  }

  // Parse URL pathname safely
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let pathname = decodeURIComponent(reqUrl.pathname);

  // Prevent directory traversal attacks
  if (pathname.includes('..') || pathname.includes('\0')) {
    setSecurityHeaders(res);
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    return res.end('Bad Request');
  }

  // Cloud Run Health Check
  if (pathname === '/healthz' || pathname === '/_health') {
    setSecurityHeaders(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'healthy',
      app: 'SJBIT Robotics Portal',
      uptime: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    }));
  }

  // Technical SEO: robots.txt
  if (pathname === '/robots.txt') {
    const robotsFile = path.join(__dirname, 'public', 'robots.txt');
    if (fs.existsSync(robotsFile)) {
      setSecurityHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=UTF-8', 'Cache-Control': 'public, max-age=86400' });
      return fs.createReadStream(robotsFile).pipe(res);
    }
  }

  // Technical SEO: sitemap.xml
  if (pathname === '/sitemap.xml') {
    const sitemapFile = path.join(__dirname, 'public', 'sitemap.xml');
    if (fs.existsSync(sitemapFile)) {
      setSecurityHeaders(res);
      res.writeHead(200, { 'Content-Type': 'application/xml; charset=UTF-8', 'Cache-Control': 'public, max-age=86400' });
      return fs.createReadStream(sitemapFile).pipe(res);
    }
  }

  // Static Assets from public/
  let candidatePath = null;
  if (pathname.startsWith('/assets/')) {
    candidatePath = path.join(__dirname, 'public', pathname);
  } else if (pathname !== '/') {
    candidatePath = path.join(__dirname, 'public', pathname);
  }

  if (candidatePath && fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
    const ext = path.extname(candidatePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    setSecurityHeaders(res, ext === '.html');
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=86400, immutable'
    });
    return fs.createReadStream(candidatePath).pipe(res);
  }

  // Default: Serve SPA index.html
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) {
    setSecurityHeaders(res, true);
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=UTF-8',
      'Cache-Control': 'no-cache, must-revalidate'
    });
    return fs.createReadStream(indexPath).pipe(res);
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, HOST, () => {
  console.log(`[SJBIT Robotics] Server listening on http://${HOST}:${PORT}`);
});
