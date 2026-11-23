'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Package only the identity boundary and its journey receiver alongside lifecycle.
// The legacy socket interface is deliberately absent: every viewer command enters UIAuth.
function buildFlows(root) {
  const read = name => JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'));
  const flows = [...read('lifecycle.json'), ...read('demonstrator/identity_flow.json'), ...read('demonstrator/journey_flow.json')];
  const ids = new Set(flows.map(n => n.id));
  for (const n of flows) {
    if (n.type === 'http in' && n.url.startsWith('/ztd/')) n.url = '/dev' + n.url;
    if (n.links) n.links = n.links.filter(id => ids.has(id));
  }
  return flows;
}

// Keep IF-08 Basic authentication. Only these exact identity routes use OIDC instead.
// The comparator is the bcrypt implementation shipped with the Node-RED runtime.
function httpAuth(user, hash, compare) {
  const viewer = new Set([
    'GET /dev/ztd/oidc/login', 'GET /dev/ztd/oidc/callback', 'GET /dev/ztd/api/session',
    'GET /dev/ztd/oidc/frontchannel-logout', 'POST /dev/ztd/oidc/backchannel-logout',
    'POST /dev/ztd/oidc/logout', 'POST /dev/ztd/api/journey'
  ]);
  for (const file of ['', 'index.html', 'index.js', 'index.css', 'vendor/vue.global.js', 'assets/favicon-32x32.png', 'assets/favicon-192x192.png', 'assets/apple-touch-icon-180x180.png', 'assets/Facis-logo.svg']) viewer.add('GET /dev/facis-demo/' + file);
  return async (req, res, next) => {
    if (viewer.has(req.method + ' ' + req.path)) return next();
    const value = req.headers.authorization || '';
    if (/^Basic [A-Za-z0-9+/]+=*$/.test(value) && value.length < 8192) {
      const plain = Buffer.from(value.slice(6), 'base64').toString('utf8');
      const i = plain.indexOf(':');
      if (i >= 0 && plain.slice(0, i) === user) {
        try { if (await compare(plain.slice(i + 1), hash)) return next(); } catch { /* fail closed */ }
      }
    }
    res.set('WWW-Authenticate', 'Basic realm="Authorization Required"');
    return res.sendStatus(401);
  };
}
module.exports = { buildFlows, httpAuth };
