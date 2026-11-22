import { describe, expect, it } from 'vitest';
import { MintClient, runChecks } from '../src/checks';
const LIVE = (process.env.MINTPROBE_LIVE ?? process.env.NUTCHECK_LIVE) === '1';
describe.skipIf(!LIVE)('free checks, live', () => {
  for (const url of ['https://testnut.cashu.space', 'https://mint.minibits.cash/Bitcoin']) {
    it(url, async () => {
      const rep = await runChecks(new MintClient(url));
      for (const r of rep.results) console.log(`${r.verdict.padEnd(5)} NUT-${r.nut} ${r.id}: ${r.detail}`);
      expect(rep.results.find((r) => r.id === 'info')!.verdict).toBe('pass');
    }, 60_000);
  }
});
