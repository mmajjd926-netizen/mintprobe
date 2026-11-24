// Records the Mintprobe walkthrough on the live site:
//   A: a real public mint, free checks (no ecash), open a row to show the exact request and reply  -> shots/video/a/*.webm
//   B: the test mint (fake Lightning) with ecash: DLEQ, fees, double spend, P2PK, HTLC...           -> shots/video/b/*.webm
//   C: the matrix of public mints                                                                   -> shots/video/c/*.webm
// Usage: node tools/demo-video.mjs [url]. Then sh tools/video/walkthrough.sh.
import { chromium } from 'playwright';
import { rmSync, mkdirSync } from 'fs';
const url = process.argv[2] ?? 'https://mmajjd926-netizen.github.io/mintprobe/';
const W = 1100, H = 760;
const b = await chromium.launch();
const t0 = Date.now();
const mark = (s) => console.log(((Date.now() - t0) / 1000).toFixed(1).padStart(5), s);
async function ctx(dir) {
  rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true });
  const c = await b.newContext({ viewport: { width: W, height: H }, recordVideo: { dir, size: { width: W, height: H } } });
  const p = await c.newPage();
  p.on('pageerror', (e) => console.log('pageerror: ' + e.message));
  return [c, p];
}
const wait = (p, ms) => p.waitForTimeout(ms);
const glide = async (p, dy, steps = 30, ms = 40) => { for (let i = 0; i < steps; i++) { await p.mouse.wheel(0, dy / steps); await wait(p, ms); } };

// ---- A
{
  const [c, p] = await ctx('shots/video/a');
  await p.goto(url); await p.waitForSelector('#url'); await wait(p, 1500); mark('A start');
  await p.click('#url'); await p.type('#url', 'https://mint.minibits.cash/Bitcoin', { delay: 45 });
  await wait(p, 400); await p.click('#go');
  await p.waitForSelector('.sum', { timeout: 60000 }); mark('A report');
  await wait(p, 1500);
  await glide(p, 420, 30, 50); await wait(p, 900);
  const warn = p.locator('details.check.warn').first();
  if (await warn.count()) { await warn.scrollIntoViewIfNeeded(); await wait(p, 600); await warn.locator('summary').click(); mark('A opened warn'); await wait(p, 600); await glide(p, 260, 20, 50); await wait(p, 3500); }
  else { const r = p.locator('details.check').nth(4); await r.locator('summary').click(); await wait(p, 4000); }
  mark('A end'); await c.close();
}
// ---- B
{
  const [c, p] = await ctx('shots/video/b');
  await p.goto(url); await p.waitForSelector('#url'); await wait(p, 800); mark('B start');
  await p.click('#url'); await p.type('#url', 'https://testnut.cashu.space', { delay: 45 });
  await wait(p, 300); await p.click('#go');
  await p.waitForSelector('#fund-go', { timeout: 60000 }); mark('B free done');
  await wait(p, 800);
  await p.locator('#fund-go').scrollIntoViewIfNeeded(); await wait(p, 1500);
  await p.click('#fund-go'); mark('B funded start');
  // follow the rows as they come in
  for (let i = 0; i < 120; i++) {
    const n = await p.locator('#frows details').count();
    if (n) await p.locator('#frows details').last().scrollIntoViewIfNeeded();
    if (!(await p.locator('#fund-go').count())) break;
    await wait(p, 500);
  }
  mark('B funded done: ' + (await p.locator('#frows details').count()) + ' rows');
  await wait(p, 1200);
  const fails = p.locator('#frows details.fail, #frows details.warn');
  if (await fails.count()) { await fails.first().scrollIntoViewIfNeeded(); await wait(p, 500); await fails.first().locator('summary').click(); await wait(p, 4000); }
  mark('B end'); await c.close();
}
// ---- C
{
  const [c, p] = await ctx('shots/video/c');
  await p.goto(url); await p.waitForSelector('table.mx', { timeout: 30000 }); await wait(p, 600); mark('C start');
  await p.locator('#matrix').scrollIntoViewIfNeeded(); await wait(p, 1200);
  await glide(p, 300, 25, 60); await wait(p, 3000);
  mark('C end'); await c.close();
}
await b.close();
