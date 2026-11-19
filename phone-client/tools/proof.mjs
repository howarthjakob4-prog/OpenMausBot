// End-to-end proof for the MausBot phone client launcher:
// serve the bundled www, pair it against the REAL local OpenMausBot server
// with a freshly minted single-use code, and screenshot each state.
import { createRequire } from 'module';
import { execSync } from 'child_process';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire('/home/hatch/workspace/projects/dots-team-ui/package.json');
const { chromium } = require('playwright');
const HERE = path.dirname(fileURLToPath(import.meta.url));
const WWW = path.join(HERE, '..', 'android-src', 'assets', 'www');
const OUT = path.join(HERE, '..', 'release-check');
fs.mkdirSync(OUT, { recursive: true });

const MIME = { '.html': 'text/html', '.png': 'image/png', '.js': 'text/javascript', '.css': 'text/css' };
const srv = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') p = '/index.html';
  const file = path.join(WWW, p);
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('nf'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});
await new Promise(r => srv.listen(8935, r));

const env = { ...process.env, PATH: process.env.HOME + '/workspace/tools/npm-global/bin:' + process.env.PATH };
const pairOut = execSync('openmausbot pair --phone android', { env, encoding: 'utf8' });
const code = (pairOut.match(/Pairing code\s+([A-Z0-9-]+)/) || [])[1];
if (!code) { console.error('FAIL: could not mint a pairing code'); process.exit(1); }
console.log('minted a single-use phone pairing code (value not printed)');

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
const page = await ctx.newPage();
const results = [];
const check = (name, ok) => { results.push([name, ok]); console.log((ok ? 'PASS' : 'FAIL'), name); };

await page.goto('http://127.0.0.1:8935/', { waitUntil: 'networkidle' });
check('launcher setup form visible', await page.locator('#setupCard').isVisible());
await page.screenshot({ path: path.join(OUT, '01-launcher-setup.png') });

await page.fill('#server', 'http://127.0.0.1:8799');
await page.fill('#code', code);
await Promise.all([
  page.waitForURL(u => u.port === '8799', { timeout: 20000 }),
  page.locator('button[type=submit]').click(),
]);
await page.waitForTimeout(2500);
console.log('landed on:', page.url());
await page.screenshot({ path: path.join(OUT, '02-pair-confirm.png') });
const pairText = (await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 300);
console.log('pair page text:', pairText);
check('pair page took the code from the link', /from the link/i.test(pairText));

// The server asks for one explicit Connect tap (anti-phishing confirm).
await page.getByRole('button', { name: /^connect$/i }).click();
await page.waitForTimeout(4000);
console.log('after Connect:', page.url());
await page.screenshot({ path: path.join(OUT, '03-workspace-after-pair.png') });
const bodyText = (await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 300);
console.log('workspace text:', bodyText);
check('reached the server workspace (port 8799)', page.url().includes('8799'));
check('workspace rendered content', bodyText.length > 20);

const devices = execSync('openmausbot devices', { env, encoding: 'utf8' });
console.log('devices output:', devices.trim().slice(0, 300));
check('server registered a paired device', !/no paired devices/i.test(devices) && /[0-9a-f]{8}-[0-9a-f]{4}/.test(devices));

await page.goto('http://127.0.0.1:8935/', { waitUntil: 'networkidle' });
check('launcher remembers the server', await page.locator('#savedCard').isVisible());
await page.screenshot({ path: path.join(OUT, '04-launcher-saved.png') });

await browser.close();
srv.close();
const fails = results.filter(([, ok]) => !ok).length;
console.log(fails === 0 ? 'ALL CHECKS PASSED' : fails + ' CHECK(S) FAILED');
process.exit(fails ? 1 : 0);
