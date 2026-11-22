import { describe, expect, it } from 'vitest';
import { MintClient, runChecks } from '../src/checks';
import { runFunded, type FundedContext } from '../src/funded';
const LIVE = (process.env.MINTPROBE_LIVE ?? process.env.NUTCHECK_LIVE) === '1';
describe.skipIf(!LIVE)('funded checks, live on testnut', () => {
  it('runs them all', async () => {
    const mint = new MintClient(process.env.MINTPROBE_MINT ?? process.env.NUTCHECK_MINT ?? 'https://testnut.cashu.space');
    const ctx: FundedContext = { mint };
    await runChecks(mint, undefined, undefined, ctx);
    const res = await runFunded(ctx);
    for (const r of res) console.log(`${r.verdict.padEnd(5)} NUT-${r.nut} ${r.id}: ${r.detail}`);
    expect(res.find((r) => r.id === 'fund')!.verdict).toBe('pass');
    expect(res.filter((r) => r.verdict === 'fail' && r.id !== 'htlc-refund')).toEqual([]);
  }, 90_000);
});
