// Loads the hosted pages in Chromium, under the content security policy they are served with, and
// drives their main flows against the browser test host (tests/browser/host), which answers requests as
// a wallet would: a cross-device check that verifies and one that fails, the return page, and the
// same-device redirect back to the same browser and to another. It fails if a page shows the wrong
// verdict, the policy refuses anything or a script errors. Expiry, refused attempts, a dropped stream and
// a failed redemption are not driven. Run it against the host:
//   BASE_URL=http://localhost:5000 node pages.mjs
import { chromium } from 'playwright';

const base = process.env.BASE_URL ?? 'http://localhost:5000';
// A verdict arrives within seconds of the answer. This bounds a page that never shows one.
const verdictTimeoutMs = 20_000;

const failures = [];

const browser = await chromium.launch();
try {
  await crossDevice(true, 'Verified ✓');
  await crossDevice(false, 'Verification failed ✗');
  await sameDevice();
} finally {
  await browser.close();
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log('every flow driven showed its verdict under its policy');

// The start page's own request, answered by a wallet on another device: the page follows it to a verdict.
async function crossDevice(valid, verdict) {
  const name = `cross-device ${valid ? 'valid' : 'invalid'}`;
  const { context, page } = await open(name);
  await load(page, `${base}/verify/start`, name);
  // The QR code is how a wallet on another device gets the request, so it must be on screen.
  if (!(await page.locator('.qr svg').isVisible())) {
    failures.push(`${name}: the QR code is not shown`);
  }
  await present((await page.textContent('.req code')).trim(), valid);
  await expectStatus(page, verdict, name);
  if (valid && !(await page.textContent('#claims')).includes('age_over_18')) {
    failures.push(`${name}: the disclosed claim is not shown`);
  }
  await checkPolicy(page, name);

  // The same session's return page, reached without a response code as a cross-device redirect lands.
  const sessionId = (await page.textContent('code')).trim();
  await load(page, `${base}/verify/${encodeURIComponent(sessionId)}/return`, `${name} return page`);
  await expectStatus(page, verdict, `${name} return page`);
  await checkPolicy(page, `${name} return page`);
  await context.close();
}

// The same-device button, the wallet's redirect back, and the redemption in this browser and another.
async function sameDevice() {
  const name = 'same-device';
  const { context, page } = await open(name);

  for (const [where, expected] of [['the same browser', 'Verified ✓'], ['another browser', 'started in another browser']]) {
    await load(page, `${base}/verify/start`, name);
    const walletUrl = await pressSameDevice(page, name);
    const answered = await present(walletUrl, true);
    const redirect = answered?.redirect_uri;
    if (!redirect?.includes('#response_code=')) {
      failures.push(`${name}: the wallet was not sent back with a response code: ${JSON.stringify(answered)}`);
      continue;
    }

    const other = where === 'another browser' ? await open(`${name} other`) : null;
    const target = other?.page ?? page;
    await load(target, redirect, `${name} return in ${where}`);
    await expectStatus(target, expected, `${name} return in ${where}`);
    if (target.url().includes('#')) {
      failures.push(`${name}: the response code stayed in the address bar in ${where}`);
    }
    await checkPolicy(target, `${name} return in ${where}`);
    await other?.context.close();
  }

  await context.close();
}

// Presses the button and returns the wallet link the page navigated to, which only a minted, bound
// request yields.
async function pressSameDevice(page, name) {
  const minted = page.waitForResponse((r) => r.url().endsWith('/verify/same-device'));
  const navigated = new Promise((resolve) => {
    page.on('request', (r) => r.url().startsWith('openid4vp:') && resolve(r.url()));
    page.on('requestfailed', (r) => r.url().startsWith('openid4vp:') && resolve(r.url()));
  });
  await page.click('#same-device');
  const { walletUrl } = await (await minted).json();
  // Chromium reports the attempt to open an openid4vp: link as a request, though nothing handles it.
  const opened = await Promise.race([navigated, page.waitForTimeout(5_000).then(() => null)]);
  if (opened !== walletUrl) {
    failures.push(`${name}: the page did not open the wallet link it was given (opened ${opened})`);
  }
  return walletUrl;
}

async function open(name) {
  const context = await browser.newContext();
  // Recorded from the page itself, so a refusal is caught whether or not the browser also logs it.
  await context.addInitScript(() => {
    window.__violations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      window.__violations.push(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => failures.push(`${name}: script error on ${page.url()}: ${error}`));
  return { context, page };
}

async function load(page, url, name) {
  const response = await page.goto(url);
  if (!response?.headers()['content-security-policy']) {
    failures.push(`${name}: served without a content security policy`);
  }
}

async function present(walletUrl, valid) {
  const response = await fetch(`${base}/test/present`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ walletUrl, valid }),
  });
  return response.json();
}

async function expectStatus(page, expected, name) {
  try {
    await page.waitForFunction(
      (text) => document.getElementById('status')?.textContent.includes(text), expected, { timeout: verdictTimeoutMs });
  } catch {
    failures.push(`${name}: expected "${expected}", the status reads "${(await page.textContent('#status'))?.trim()}"`);
  }

  // The stylesheet is inline and allowed by hash: a refused one leaves the status unstyled.
  const styled = await page.evaluate(() => getComputedStyle(document.getElementById('status')).borderTopLeftRadius !== '0px');
  if (!styled) {
    failures.push(`${name}: the stylesheet did not apply`);
  }
}

async function checkPolicy(page, name) {
  for (const violation of await page.evaluate(() => window.__violations)) {
    failures.push(`${name}: the policy refused ${violation}`);
  }
}
