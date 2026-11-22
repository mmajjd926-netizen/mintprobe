// Run the free checks against public mints and write public/matrix.json for the "Mints today" table.
// Usage: node --experimental-strip-types tools/matrix.mjs
import { writeFileSync } from 'fs';
import { MintClient, runChecks } from '../src/checks.ts';
const MINTS = [
  'https://testnut.cashu.space', 'https://nofees.testnut.cashu.space', 'https://mint.minibits.cash/Bitcoin', 'https://mint.coinos.io',
  'https://8333.space:3338', 'https://mint.macadamia.cash', 'https://stablenut.umint.cash', 'https://mint.lnvoltz.com',
  'https://mint.agorist.space', 'https://mint.cubabitcoin.org', 'https://mint.lnwallet.app', 'https://mint.hashu.io', 'https://mint.gitvid.net',
  'https://mint.cashu.chat', 'https://forge.flashapp.me', 'https://mint.mikelcalvo.net', 'https://cashu.mutinynet.com', 'https://nofee.testnut.cashu.space',
  'https://mint.westernbtc.com', 'https://mint.bitcoinmints.com', 'https://legend.lnbits.com/cashu/api/v1/4gr9Xcmz3XEkUNwiBiQGoC',
];
const out = [];
await Promise.all(MINTS.map(async (url) => {
  const rep = await runChecks(new MintClient(url, undefined, 12000));
  const info = rep.results.find((r) => r.id === 'info');
  if (info.verdict !== 'pass') { console.log('skip', url, info.detail); return; }
  for (const r of rep.results) delete r.exchange;
  out.push(rep);
  console.log(url, rep.results.map((r) => r.verdict[0]).join(''));
}));
out.sort((a, b) => a.mint.localeCompare(b.mint));
writeFileSync('public/matrix.json', JSON.stringify({ generated: Math.floor(Date.now() / 1000), reports: out }, null, 1));
console.log('wrote', out.length);
