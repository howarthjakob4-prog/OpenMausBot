// Harness proof for the v0.1.3 launcher page: serves assets/www locally and
// drives it in a phone-sized Chromium with a stubbed FerrumRelay bridge.
// (The native side is proven separately: Java vectors 40/40 + the JS live
// proof of the same protocol. The phone itself is the final verdict.)
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";

const require = createRequire("/home/hatch/workspace/projects/dots-team-ui/package.json");
const { chromium } = require("playwright");
const WWW = "/home/hatch/workspace/projects/openmausbot-phone/android-src/assets/www";
const OUT = "/home/hatch/workspace/projects/openmausbot-phone/release-check";
const MIME = { ".html": "text/html", ".png": "image/png", ".js": "text/javascript" };

const server = createServer(async (req, res) => {
  const path = req.url.split("?")[0] === "/" ? "/index.html" : req.url.split("?")[0];
  try {
    const data = await readFile(join(WWW, path));
    res.writeHead(200, { "Content-Type": MIME[extname(path)] ?? "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch({
  executablePath: "/home/hatch/.cache/ms-playwright/chromium-1254/chrome-linux64/chrome",
});
const page = await browser.newPage({ viewport: { width: 412, height: 915 } });
let failures = 0;
const check = (name, ok) => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}`);
  if (!ok) failures++;
};

// The stub bridge: records calls, pretends a server is saved.
await page.addInitScript(() => {
  window.__calls = [];
  window.FerrumRelay = {
    pair(link) { window.__calls.push(["pair", link]); window.__relay("pairing", null); },
    reconnect() { window.__calls.push(["reconnect"]); },
    forget() { window.__calls.push(["forget"]); },
    savedServerName() { return "htch-runtime"; },
  };
});

// 1. Unpaired state: shield, paste box, saved-server buttons armed.
await page.goto(base + "/");
await page.waitForTimeout(300);
check("unpaired: paste box visible", await page.isVisible("#pasteCard"));
check("unpaired: retry shown (saved server)", await page.isVisible("#retryBtn"));
check("unpaired: forget shown", await page.isVisible("#forgetBtn"));
await page.screenshot({ path: `${OUT}/09-v013-launcher.png` });

// 2. Paste flow calls the bridge with the pasted link.
await page.fill("#link", "openmausbot://pair?token=omb_pair_test&e2e=AAAA");
await page.click("#pasteCard button[type=submit]");
await page.waitForTimeout(200);
const calls = await page.evaluate(() => window.__calls);
check("paste -> bridge.pair(link)", calls.some((c) => c[0] === "pair" && c[1].startsWith("openmausbot://pair")));
check("pairing status shows", (await page.textContent("#statusLine")).includes("Pairing"));

// 3. Deep-link state: auto-pairs on load.
await page.goto(base + "/?state=pair&pair=" + encodeURIComponent("openmausbot://pair?token=omb_pair_test&e2e=BBBB"));
await page.waitForTimeout(300);
const calls2 = await page.evaluate(() => window.__calls);
check("state=pair auto-calls bridge.pair", calls2.some((c) => c[0] === "pair" && c[1].includes("BBBB")));

// 4. Connecting state: pulsing status, no paste box.
await page.goto(base + "/?state=connecting");
await page.waitForTimeout(200);
check("connecting: status visible", await page.isVisible("#statusLine"));
check("connecting: paste box hidden", !(await page.isVisible("#pasteCard")));
await page.screenshot({ path: `${OUT}/10-v013-connecting.png` });

// 5. Error state: message + paste box + buttons.
await page.goto(base + "/?state=error");
await page.waitForTimeout(200);
check("error: err box visible", await page.isVisible("#errBox"));
check("error: paste box visible", await page.isVisible("#pasteCard"));
await page.screenshot({ path: `${OUT}/11-v013-error.png` });

// 6. Removed state.
await page.goto(base + "/?state=removed");
await page.waitForTimeout(200);
check("removed: message mentions removed", (await page.textContent("#errBox")).includes("removed"));

await browser.close();
server.close();
console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} FAILURES`);
process.exit(failures ? 1 : 0);
