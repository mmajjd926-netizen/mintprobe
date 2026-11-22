// Checks that move real (or test) ecash: mint, DLEQ, fees, double spend, spending conditions.
// On test mints that pay their own invoices (testnut) they run by themselves; on a real mint the
// caller pays a small invoice first.
import {
  LockBuilder,
  MintQuoteState,
  OutputData,
  Wallet,
  createHTLCHash,
  hasValidDleq,
  hashToCurve,
  signP2PKProofs,
  type Proof,
} from '@cashu/cashu-ts';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { MintClient, type Context, type Exchange, type Result, type Verdict, ERROR_CODES } from './checks.ts';

export interface FundedState {
  wallet: Wallet;
  pool: Proof[];
  keyset: { id: string; keys: Record<string, string>; fee: number };
}

export interface FundedContext extends Context {
  funded?: FundedState;
  pay?: (invoice: string, amount: number) => void; // show an invoice to the user when the mint won't pay itself
  waitMs?: number;
}

type Out = { verdict: Verdict; detail: string };
interface FundedDef {
  id: string;
  nut: string;
  title: string;
  run: (ctx: FundedContext) => Promise<Out>;
}

const num = (a: unknown) => Number((a as { toString(): string }).toString());
const sum = (ps: Proof[]) => ps.reduce((s, p) => s + num(p.amount), 0);
const plain = (p: Proof) => ({ amount: num(p.amount), id: p.id, secret: p.secret, C: p.C, ...(p.witness ? { witness: typeof p.witness === 'string' ? p.witness : JSON.stringify(p.witness) } : {}) });
const Y = (p: Proof) => bytesToHex(hashToCurve(utf8ToBytes(p.secret)).toBytes(true));
const codeOf = (ex: Exchange) => (ex.response as { code?: number })?.code;
const fmt = (ex: Exchange) => {
  const c = codeOf(ex);
  const d = String((ex.response as { detail?: string })?.detail ?? '').slice(0, 90);
  return `HTTP ${ex.status}${c !== undefined ? ` code ${c}${ERROR_CODES[c] ? ` (${ERROR_CODES[c]})` : ''}` : ''}${d ? ` "${d}"` : ''}`;
};
const fee = (st: FundedState, n: number) => Math.ceil((n * st.keyset.fee) / 1000);

/** Blinded messages worth `amount` (random secrets; we never unblind them). */
function outputs(st: FundedState, amount: number) {
  if (amount <= 0) return [];
  return OutputData.createRandomData(amount, { id: st.keyset.id, keys: st.keyset.keys }).map((o) => ({
    amount: num(o.blindedMessage.amount),
    id: st.keyset.id,
    B_: o.blindedMessage.B_,
  }));
}

/** Take proofs worth at least `amount` out of the pool, swapping to exact change with the wallet if needed. */
async function take(st: FundedState, amount: number): Promise<Proof[]> {
  const { keep, send } = await st.wallet.ops.send(amount, st.pool).includeFees(true).run();
  st.pool = keep;
  return send;
}

const newKey = () => {
  const sk = schnorr.utils.randomSecretKey();
  return { sk: bytesToHex(sk), pk: bytesToHex(secp256k1.getPublicKey(sk, true)) };
};

export const FUNDED_CHECKS: FundedDef[] = [
  {
    id: 'fund',
    nut: '04',
    title: 'Mint 100 sat of ecash (quote → paid → mint)',
    run: async (ctx) => {
      const ks = ctx.keysets?.find((k) => k.active && k.unit === 'sat');
      const keys = ctx.keys?.find((k) => k.id === ks?.id);
      if (!ks || !keys) return { verdict: 'skip', detail: 'no active sat keyset' };
      const wallet = new Wallet(ctx.mint.url, { unit: 'sat' });
      await wallet.loadMint();
      const q = await wallet.createMintQuoteBolt11(100);
      let paid = q.state === MintQuoteState.PAID;
      if (!paid) ctx.pay?.(q.request, 100);
      const until = Date.now() + (ctx.waitMs ?? 15000);
      let st = q;
      while (!paid && Date.now() < until) {
        await new Promise((r) => setTimeout(r, 1500));
        st = await wallet.checkMintQuoteBolt11(q.quote);
        paid = st.state === MintQuoteState.PAID;
      }
      if (!paid) return { verdict: 'skip', detail: 'the invoice was not paid (test mints pay their own; pay it to run the rest)' };
      const proofs = await wallet.mintProofsBolt11(100, st);
      ctx.funded = { wallet, pool: proofs, keyset: { id: ks.id, keys: keys.keys, fee: ks.input_fee_ppk ?? 0 } };
      return sum(proofs) === 100 ? { verdict: 'pass', detail: `100 sat in ${proofs.length} proofs` } : { verdict: 'fail', detail: `minted ${sum(proofs)} instead of 100` };
    },
  },
  {
    id: 'dleq',
    nut: '12',
    title: 'Every signature comes with a valid DLEQ proof',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      const without = st.pool.filter((p) => !p.dleq);
      const bad = st.pool.filter((p) => p.dleq && !hasValidDleq(p, { id: st.keyset.id, keys: st.keyset.keys }));
      if (bad.length) return { verdict: 'fail', detail: `${bad.length} of ${st.pool.length} DLEQ proofs do not verify` };
      if (without.length) return { verdict: ctx.info?.nuts?.['12']?.supported ? 'fail' : 'warn', detail: `${without.length} signatures without DLEQ${ctx.info?.nuts?.['12']?.supported ? ' although NUT-12 is advertised' : ''}` };
      return { verdict: 'pass', detail: `${st.pool.length} of ${st.pool.length} verify` };
    },
  },
  {
    id: 'fee-exact',
    nut: '02',
    title: 'Swap fee is exactly ceil(Σ input_fee_ppk / 1000)',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      const inputs = await take(st, 8 + fee(st, 4));
      const total = sum(inputs);
      const f = fee(st, inputs.length);
      const over = await ctx.mint.call('POST', '/v1/swap', { inputs: inputs.map(plain), outputs: outputs(st, total - f + 1) });
      if (over.status === 200) return { verdict: 'fail', detail: `paid out ${total - f + 1} for ${total} in with fee ${f}: the mint undercharged` };
      if (f > 0) {
        const under = await ctx.mint.call('POST', '/v1/swap', { inputs: inputs.map(plain), outputs: outputs(st, total - f - 1) });
        if (under.status === 200) return { verdict: 'fail', detail: `accepted ${total - f - 1} out for ${total} in with fee ${f}: inputs must equal outputs + fee` };
      }
      const ok = await ctx.mint.call('POST', '/v1/swap', { inputs: inputs.map(plain), outputs: outputs(st, total - f) });
      if (ok.status !== 200) return { verdict: 'fail', detail: `the exact swap (${total} in, ${total - f} out, fee ${f}) was refused: ${fmt(ok)}` };
      (ctx as FundedContext & { spent?: Proof[] }).spent = inputs;
      return { verdict: over.status === 400 && codeOf(over) === 11005 ? 'pass' : 'warn', detail: `${inputs.length} inputs, fee ${f} sat; overpay refused with ${fmt(over)}` };
    },
  },
  {
    id: 'double-spend',
    nut: '03',
    title: 'Spending the same proofs twice is refused with 11001',
    run: async (ctx) => {
      const st = ctx.funded;
      const spent = (ctx as FundedContext & { spent?: Proof[] }).spent;
      if (!st || !spent) return { verdict: 'skip', detail: 'no spent proofs' };
      const ex = await ctx.mint.call('POST', '/v1/swap', { inputs: spent.map(plain), outputs: outputs(st, sum(spent) - fee(st, spent.length)) });
      if (ex.status === 200) return { verdict: 'fail', detail: 'DOUBLE SPEND ACCEPTED' };
      return codeOf(ex) === 11001 ? { verdict: 'pass', detail: fmt(ex) } : { verdict: 'warn', detail: `refused, but ${fmt(ex)}; spec code is 11001` };
    },
  },
  {
    id: 'checkstate-spent',
    nut: '07',
    title: 'checkstate reports the spent proofs as SPENT',
    run: async (ctx) => {
      const spent = (ctx as FundedContext & { spent?: Proof[] }).spent;
      if (!spent) return { verdict: 'skip', detail: 'no spent proofs' };
      const ex = await ctx.mint.call('POST', '/v1/checkstate', { Ys: spent.map(Y) });
      const states = (ex.response as { states?: { state: string }[] })?.states ?? [];
      return states.length === spent.length && states.every((s) => s.state === 'SPENT') ? { verdict: 'pass', detail: `${states.length} SPENT` } : { verdict: 'fail', detail: JSON.stringify(states).slice(0, 160) };
    },
  },
  {
    id: 'p2pk',
    nut: '11',
    title: 'P2PK: locked proofs need the key; with a signature they spend',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      if (!ctx.info?.nuts?.['11']?.supported) return { verdict: 'skip', detail: 'NUT-11 not advertised' };
      const k = newKey();
      const { keep, send } = await st.wallet.ops.send(4, st.pool).asP2PK({ pubkey: k.pk }).includeFees(true).run();
      st.pool = keep;
      const f = fee(st, send.length);
      const bare = await ctx.mint.call('POST', '/v1/swap', { inputs: send.map(plain), outputs: outputs(st, sum(send) - f) });
      if (bare.status === 200) return { verdict: 'fail', detail: 'P2PK-locked proofs spent WITHOUT a signature' };
      // A real Schnorr signature over the secret, but from another key (wallet libraries refuse to make one).
      const other = schnorr.utils.randomSecretKey();
      const wrong = send.map((p) => ({ ...plain(p), witness: JSON.stringify({ signatures: [bytesToHex(schnorr.sign(sha256(utf8ToBytes(p.secret)), other))] }) }));
      const w = await ctx.mint.call('POST', '/v1/swap', { inputs: wrong, outputs: outputs(st, sum(send) - f) });
      if (w.status === 200) return { verdict: 'fail', detail: 'spent with a signature from the WRONG key' };
      const signed = signP2PKProofs(send, k.sk);
      const ok = await ctx.mint.call('POST', '/v1/swap', { inputs: signed.map(plain), outputs: outputs(st, sum(send) - f) });
      const note = [bare, w].some((x) => codeOf(x) === 20008) ? ' (20008 is the NUT-20 mint-quote code; NUT-11 has none of its own)' : '';
      return ok.status === 200 ? { verdict: 'pass', detail: `no witness: ${fmt(bare)}; wrong key: ${fmt(w)}; right key: spent${note}` } : { verdict: 'fail', detail: `the right signature was refused: ${fmt(ok)}` };
    },
  },
  {
    id: 'htlc',
    nut: '14',
    title: 'HTLC: wrong preimage refused, right one spends, NUT-07 returns the witness',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      if (!ctx.info?.nuts?.['14']?.supported) return { verdict: 'skip', detail: 'NUT-14 not advertised' };
      const { hash, preimage } = createHTLCHash();
      const lock = new LockBuilder().addHashlock(hash);
      const { keep, send } = await st.wallet.ops.send(4, st.pool).asLocked(lock).includeFees(true).run();
      st.pool = keep;
      const f = fee(st, send.length);
      const withPre = (pre: string) => send.map((p) => ({ ...plain(p), witness: JSON.stringify({ preimage: pre, signatures: [] }) }));
      const wrong = await ctx.mint.call('POST', '/v1/swap', { inputs: withPre(createHTLCHash().preimage), outputs: outputs(st, sum(send) - f) });
      if (wrong.status === 200) return { verdict: 'fail', detail: 'spent with a WRONG preimage' };
      const ok = await ctx.mint.call('POST', '/v1/swap', { inputs: withPre(preimage), outputs: outputs(st, sum(send) - f) });
      if (ok.status !== 200) return { verdict: 'fail', detail: `the right preimage was refused: ${fmt(ok)}` };
      const cs = await ctx.mint.call('POST', '/v1/checkstate', { Ys: send.map(Y) });
      const wit = (cs.response as { states?: { witness?: string }[] })?.states?.[0]?.witness;
      const shows = typeof wit === 'string' && wit.includes(preimage);
      return { verdict: shows ? 'pass' : 'warn', detail: `wrong preimage: ${fmt(wrong)}; right: spent; checkstate witness ${shows ? 'carries the preimage' : 'MISSING (NUT-07 says it SHOULD be returned)'}` };
    },
  },
  {
    id: 'htlc-refund',
    nut: '14',
    title: 'HTLC refund after locktime with the refund key alone',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      if (!ctx.info?.nuts?.['14']?.supported) return { verdict: 'skip', detail: 'NUT-14 not advertised' };
      const k = newKey();
      const lock = new LockBuilder()
        .addHashlock(createHTLCHash().hash)
        .lockUntil(Math.floor(Date.now() / 1000) + 2)
        .addRefundPubkey(k.pk);
      const { keep, send } = await st.wallet.ops.send(4, st.pool).asLocked(lock).includeFees(true).run();
      st.pool = keep;
      const f = fee(st, send.length);
      const early = await ctx.mint.call('POST', '/v1/swap', { inputs: signP2PKProofs(send, k.sk).map(plain), outputs: outputs(st, sum(send) - f) });
      if (early.status === 200) return { verdict: 'fail', detail: 'refund key spent the HTLC BEFORE the locktime' };
      await new Promise((r) => setTimeout(r, 3500));
      // NUT-14: after the locktime the refund path needs only the refund signatures. A wallet that
      // signs as for P2PK sends a witness with "signatures" and no "preimage".
      const sigOnly = signP2PKProofs(send, k.sk);
      const ex = await ctx.mint.call('POST', '/v1/swap', { inputs: sigOnly.map(plain), outputs: outputs(st, sum(send) - f) });
      if (ex.status === 200) return { verdict: 'pass', detail: `before locktime: ${fmt(early)}; after: refunded with a signature-only witness` };
      const withEmpty = sigOnly.map((p) => {
        const w = typeof p.witness === 'string' ? JSON.parse(p.witness) : p.witness;
        return { ...plain(p), witness: JSON.stringify({ preimage: '', signatures: w?.signatures ?? [] }) };
      });
      const ex2 = await ctx.mint.call('POST', '/v1/swap', { inputs: withEmpty, outputs: outputs(st, sum(send) - f) });
      return {
        verdict: 'fail',
        detail: `signature-only refund witness refused: ${fmt(ex)}.${ex2.status === 200 ? ' The same refund with "preimage": "" passes, so the mint parses a witness without "preimage" as P2PK (fixed in CDK main by cashubtc/cdk#2641).' : ` With "preimage": "" too: ${fmt(ex2)}.`}`,
      };
    },
  },
];

export async function runFunded(ctx: FundedContext, onResult?: (r: Result) => void): Promise<Result[]> {
  const out: Result[] = [];
  for (const d of FUNDED_CHECKS) {
    const before = ctx.mint.log.length;
    let r: Result;
    try {
      r = { id: d.id, nut: d.nut, title: d.title, ...(await d.run(ctx)) };
    } catch (e) {
      r = { id: d.id, nut: d.nut, title: d.title, verdict: 'fail', detail: `error: ${e instanceof Error ? e.message : String(e)}` };
    }
    r.exchange = ctx.mint.log.slice(before);
    out.push(r);
    onResult?.(r);
    if (d.id === 'fund' && r.verdict !== 'pass') break;
  }
  return out;
}

export { MintClient };
