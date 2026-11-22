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
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
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

/** NUT-11 SIG_ALL message: secret‖C of every input, then amount‖B_ of every output (the unframed transcript of CDK ≥ 0.14 and Nutshell > 0.20.2). */
export const sigAllMessage = (ins: { secret: string; C: string }[], outs: { amount: number; B_: string }[], quoteId?: string) =>
  ins.map((p) => p.secret + p.C).join('') + outs.map((o) => String(o.amount) + o.B_).join('') + (quoteId ?? '');

/** NUT-20: the message signed for a pubkey-locked mint quote is sha256(quote id || B_0 || … || B_n), the B_ as hex strings. */
export const nut20Digest = (quote: string, outs: { B_: string }[]) => sha256(utf8ToBytes(quote + outs.map((o) => o.B_).join('')));

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
    id: 'melt-change',
    nut: '05/08',
    title: 'Melt pays an invoice; the unused fee reserve comes back as change',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      if (!ctx.info?.nuts?.['5']?.methods?.some((m: { method: string }) => m.method === 'bolt11')) return { verdict: 'skip', detail: 'bolt11 melting not advertised' };
      // An invoice from this very mint (a mint quote), so the payment settles inside the mint.
      const inv = await ctx.mint.call('POST', '/v1/mint/quote/bolt11', { amount: 5, unit: 'sat' });
      const request = (inv.response as { request?: string })?.request;
      if (!request) return { verdict: 'skip', detail: `no invoice to pay: ${fmt(inv)}` };
      const mq = await ctx.mint.call('POST', '/v1/melt/quote/bolt11', { request, unit: 'sat' });
      const q = mq.response as { quote?: string; amount?: number; fee_reserve?: number };
      if (mq.status !== 200 || !q.quote || typeof q.amount !== 'number') return { verdict: 'fail', detail: `melt quote refused: ${fmt(mq)}` };
      if (q.amount !== 5) return { verdict: 'fail', detail: `melt quote for a 5 sat invoice asks ${q.amount} sat` };
      const reserve = q.fee_reserve ?? 0;
      const inputs = await take(st, q.amount + reserve + 1); // 1 sat extra on top of the reserve, so change is due either way
      const over = sum(inputs) - fee(st, inputs.length) - q.amount; // what the mint holds beyond the invoice
      // NUT-08: blank outputs, ceil(log2(overpaid)) of them (at least 1); their amounts are ignored.
      const n = Math.max(1, Math.ceil(Math.log2(over)));
      const blanks = Array.from({ length: n }, () => outputs(st, 1)[0]);
      const ex = await ctx.mint.call('POST', '/v1/melt/bolt11', { quote: q.quote, inputs: inputs.map(plain), outputs: blanks });
      const r = ex.response as { state?: string; paid?: boolean; change?: { amount: number }[] };
      if (ex.status !== 200) return { verdict: 'fail', detail: `melt refused: ${fmt(ex)}` };
      if (r.state !== 'PAID' && r.paid !== true) return { verdict: 'fail', detail: `melt answered 200 with state ${r.state}` };
      const change = (r.change ?? []).reduce((a, c) => a + num(c.amount), 0);
      const powers = (r.change ?? []).every((c) => (num(c.amount) & (num(c.amount) - 1)) === 0 && num(c.amount) > 0);
      const after = await ctx.mint.call('GET', `/v1/melt/quote/bolt11/${q.quote}`);
      const later = (after.response as { state?: string })?.state;
      const note = `invoice 5 sat, reserve ${reserve}, ${sum(inputs)} in (input fee ${fee(st, inputs.length)}), ${n} blank output(s) → change ${change} sat; quote now ${later}`;
      if (change > over) return { verdict: 'fail', detail: `the mint returned MORE than it held: ${note}` };
      if (change < over - reserve) return { verdict: 'fail', detail: `change short by ${over - reserve - change} sat beyond the fee reserve: ${note}` };
      if (!powers) return { verdict: 'fail', detail: `change amounts are not powers of two: ${note}` };
      if (later !== 'PAID') return { verdict: 'warn', detail: `the quote does not read PAID afterwards: ${note}` };
      return { verdict: 'pass', detail: note };
    },
  },
  {
    id: 'nut19-replay',
    nut: '19',
    title: 'Replaying the same swap within the TTL returns the cached signatures',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      const n19 = ctx.info?.nuts?.['19'] as { ttl?: number | null; cached_endpoints?: { method: string; path: string }[] } | undefined;
      const cached = !!n19?.cached_endpoints?.some((e) => e.method === 'POST' && e.path === '/v1/swap');
      const inputs = await take(st, 4 + fee(st, 3));
      const body = { inputs: inputs.map(plain), outputs: outputs(st, sum(inputs) - fee(st, inputs.length)) };
      const first = await ctx.mint.call('POST', '/v1/swap', body);
      if (first.status !== 200) return { verdict: 'fail', detail: `the swap itself was refused: ${fmt(first)}` };
      // The same bytes again, as a wallet would resend after a lost response.
      const again = await ctx.mint.call('POST', '/v1/swap', body);
      const sigs = (ex: Exchange) => JSON.stringify((ex.response as { signatures?: { C_: string }[] })?.signatures?.map((x) => x.C_) ?? []);
      if (!cached) {
        if (again.status === 200) return { verdict: 'warn', detail: 'NUT-19 caching for /v1/swap is not advertised, yet the replay was answered 200' };
        return { verdict: 'skip', detail: `NUT-19 caching for /v1/swap not advertised; replay: ${fmt(again)}` };
      }
      if (again.status !== 200) return { verdict: 'fail', detail: `NUT-19 advertises /v1/swap as cached (ttl ${n19?.ttl ?? 'none'}), but the replay got ${fmt(again)}: a wallet that lost the first response cannot recover its outputs` };
      return sigs(first) === sigs(again)
        ? { verdict: 'pass', detail: `replay answered with the same ${inputs.length > 1 ? 'signatures' : 'signature'} (ttl ${n19?.ttl ?? 'none'} s)` }
        : { verdict: 'fail', detail: 'replay answered 200 but with DIFFERENT signatures for the same outputs' };
    },
  },
  {
    id: 'nut20-signed-quote',
    nut: '20',
    title: 'A mint quote locked to a pubkey mints only with its signature',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      if (!ctx.info?.nuts?.['20']?.supported) return { verdict: 'skip', detail: 'NUT-20 not advertised' };
      const k = newKey();
      const q = await ctx.mint.call('POST', '/v1/mint/quote/bolt11', { amount: 4, unit: 'sat', pubkey: k.pk });
      const quote = q.response as { quote?: string; state?: string; pubkey?: string };
      if (q.status !== 200 || !quote.quote) return { verdict: 'fail', detail: `a quote with a pubkey was refused: ${fmt(q)}` };
      let state = quote.state;
      for (let i = 0; i < 6 && state !== 'PAID'; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        state = ((await ctx.mint.call('GET', `/v1/mint/quote/bolt11/${quote.quote}`)).response as { state?: string })?.state;
      }
      if (state !== 'PAID') return { verdict: 'skip', detail: 'needs a second paid invoice (runs by itself on test mints that pay their own)' };
      const outs = outputs(st, 4);
      const digest = nut20Digest(quote.quote, outs);
      const none = await ctx.mint.call('POST', '/v1/mint/bolt11', { quote: quote.quote, outputs: outs });
      if (none.status === 200) return { verdict: 'fail', detail: 'a pubkey-locked quote was minted WITHOUT a signature: anyone who sees the quote id can take the ecash' };
      const wrong = await ctx.mint.call('POST', '/v1/mint/bolt11', { quote: quote.quote, outputs: outs, signature: bytesToHex(schnorr.sign(digest, schnorr.utils.randomSecretKey())) });
      if (wrong.status === 200) return { verdict: 'fail', detail: 'a pubkey-locked quote was minted with a signature from the WRONG key' };
      const ok = await ctx.mint.call('POST', '/v1/mint/bolt11', { quote: quote.quote, outputs: outs, signature: bytesToHex(schnorr.sign(digest, hexToBytes(k.sk))) });
      if (ok.status !== 200) return { verdict: 'fail', detail: `the right signature was refused: ${fmt(ok)}` };
      const codes = [none, wrong].map(codeOf);
      const echo = quote.pubkey === k.pk ? '' : '; the quote response does not echo the pubkey (NUT-20 says it MUST)';
      return {
        verdict: codes.every((c) => c === 20008) && !echo ? 'pass' : 'warn',
        detail: `no signature: ${fmt(none)}; wrong key: ${fmt(wrong)}; right key: minted${codes.every((c) => c === 20008) ? '' : ' (spec code is 20008)'}${echo}`,
      };
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
    id: 'p2pk-multisig',
    nut: '11',
    title: 'P2PK 2-of-2: one signature refused, the same signature twice refused, two keys spend',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      if (!ctx.info?.nuts?.['11']?.supported) return { verdict: 'skip', detail: 'NUT-11 not advertised' };
      const a = newKey();
      const b = newKey();
      const { keep, send } = await st.wallet.ops.send(4, st.pool).asP2PK({ pubkey: [a.pk, b.pk], requiredSignatures: 2 }).includeFees(true).run();
      st.pool = keep;
      const f = fee(st, send.length);
      const sig = (p: Proof, sk: string) => bytesToHex(schnorr.sign(sha256(utf8ToBytes(p.secret)), hexToBytes(sk)));
      const withSigs = (keys: string[]) => send.map((p) => ({ ...plain(p), witness: JSON.stringify({ signatures: keys.map((k) => sig(p, k)) }) }));
      const swap = (inputs: unknown[]) => ctx.mint.call('POST', '/v1/swap', { inputs, outputs: outputs(st, sum(send) - f) });
      const one = await swap(withSigs([a.sk]));
      if (one.status === 200) return { verdict: 'fail', detail: '2-of-2 proofs spent with ONE signature' };
      // BIP-340 signing here is deterministic, so the same key twice gives the same signature: a mint must count signers, not signatures.
      const dup = await swap(withSigs([a.sk, a.sk]));
      if (dup.status === 200) return { verdict: 'fail', detail: '2-of-2 proofs spent with the SAME key\'s signature twice (signatures counted, not signers)' };
      const both = await swap(withSigs([b.sk, a.sk]));
      return both.status === 200
        ? { verdict: 'pass', detail: `one signature: ${fmt(one)}; same one twice: ${fmt(dup)}; both keys (in reverse order): spent` }
        : { verdict: 'fail', detail: `two valid signatures were refused: ${fmt(both)}` };
    },
  },
  {
    id: 'p2pk-sigall',
    nut: '11',
    title: 'P2PK SIG_ALL: input-only signatures refused, signed outputs cannot be swapped, the right signature spends',
    run: async (ctx) => {
      const st = ctx.funded;
      if (!st) return { verdict: 'skip', detail: 'no ecash' };
      if (!ctx.info?.nuts?.['11']?.supported) return { verdict: 'skip', detail: 'NUT-11 not advertised' };
      const k = newKey();
      const { keep, send } = await st.wallet.ops.send(4, st.pool).asP2PK({ pubkey: k.pk, sigFlag: 'SIG_ALL' }).includeFees(true).run();
      st.pool = keep;
      const f = fee(st, send.length);
      const outsA = outputs(st, sum(send) - f);
      const outsB = outputs(st, sum(send) - f); // someone else's outputs, same amounts
      const sigOn = (msg: string) => bytesToHex(schnorr.sign(sha256(utf8ToBytes(msg)), hexToBytes(k.sk)));
      const msgFor = (outs: { amount: number; B_: string }[]) => sigAllMessage(send, outs);
      const witnessed = (sig: string) => send.map((p) => ({ ...plain(p), witness: JSON.stringify({ signatures: [sig] }) }));
      // 1. signatures over each secret, as for SIG_INPUTS: they do not cover the outputs
      const inputsOnly = send.map((p) => ({ ...plain(p), witness: JSON.stringify({ signatures: [sigOn(p.secret)] }) }));
      const r1 = await ctx.mint.call('POST', '/v1/swap', { inputs: inputsOnly, outputs: outsA });
      if (r1.status === 200) return { verdict: 'fail', detail: 'SIG_ALL proofs spent with SIG_INPUTS signatures (outputs not covered)' };
      // 2. a valid SIG_ALL signature for outputs A, sent with outputs B: what SIG_ALL exists to stop
      const sigA = sigOn(msgFor(outsA));
      const r2 = await ctx.mint.call('POST', '/v1/swap', { inputs: witnessed(sigA), outputs: outsB });
      if (r2.status === 200) return { verdict: 'fail', detail: 'a SIG_ALL signature for one set of outputs spent the proofs into DIFFERENT outputs' };
      // 3. the right one
      const r3 = await ctx.mint.call('POST', '/v1/swap', { inputs: witnessed(sigA), outputs: outsA });
      const refused = `input-only signatures: ${fmt(r1)}; outputs swapped after signing: ${fmt(r2)}`;
      if (r3.status === 200) return { verdict: 'pass', detail: `${refused}; signed outputs: spent` };
      // Older mints (Nutshell ≤ 0.20.2, CDK < 0.14) sign the legacy transcript: every secret, then every B_.
      const legacy = send.map((p) => p.secret).join('') + outsA.map((o) => o.B_).join('');
      const r4 = await ctx.mint.call('POST', '/v1/swap', { inputs: witnessed(sigOn(legacy)), outputs: outsA });
      if (r4.status === 200)
        return { verdict: 'warn', detail: `the current SIG_ALL message (secret‖C of inputs, amount‖B_ of outputs) was refused: ${fmt(r3)}; the legacy one (secrets‖B_) spends, so wallets on the current spec (cashu-ts 4) cannot spend SIG_ALL ecash here. ${refused}` };
      return { verdict: 'fail', detail: `the right SIG_ALL signature was refused: ${fmt(r3)}, the legacy transcript too: ${fmt(r4)}` };
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
