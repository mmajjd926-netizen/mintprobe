// Mintprobe: conformance checks for a Cashu mint, run from a browser or Node.
// Every check talks to the mint over plain HTTP and judges the answer against the NUT text, so the
// verdict doesn't depend on any one wallet library. (cashu-ts is used only to build valid ecash for the
// funded checks.)
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export type Verdict = 'pass' | 'fail' | 'warn' | 'skip' | 'info';

export interface Result {
  id: string;
  nut: string; // "06", "02", …
  title: string;
  verdict: Verdict;
  detail: string;
  exchange?: Exchange[]; // the HTTP requests this check made
}

export interface Exchange {
  method: string;
  path: string;
  body?: unknown;
  status: number;
  response: unknown;
  cors?: boolean; // Access-Control-Allow-Origin present (Node only can see this)
}

type Fetch = typeof fetch;

export class MintClient {
  readonly url: string;
  readonly log: Exchange[] = [];
  private f: Fetch;
  private timeoutMs: number;
  constructor(url: string, f: Fetch = (...a) => fetch(...a), timeoutMs = 15000) {
    this.url = url.trim().replace(/\/+$/, '');
    this.f = f;
    this.timeoutMs = timeoutMs;
  }

  async call(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Exchange> {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const r = await this.f(this.url + path, {
        method,
        headers: body === undefined ? { Accept: 'application/json' } : { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: ctl.signal,
      });
      const text = await r.text();
      let response: unknown = text;
      try {
        response = JSON.parse(text);
      } catch {
        /* not JSON: keep text */
      }
      const ex: Exchange = { method, path, body, status: r.status, response, cors: r.headers.get('access-control-allow-origin') != null || undefined };
      this.log.push(ex);
      return ex;
    } finally {
      clearTimeout(t);
    }
  }
}

// ---------- spec helpers ----------
export const ERROR_CODES: Record<number, string> = {
  10001: 'Proof verification failed',
  11001: 'Proofs already spent',
  11002: 'Proofs are pending',
  11003: 'Outputs already signed',
  11004: 'Outputs are pending',
  11005: 'Transaction is not balanced',
  11006: 'Amount outside of limit range',
  11007: 'Duplicate inputs provided',
  11008: 'Duplicate outputs provided',
  11009: 'Inputs/Outputs of multiple units',
  11010: 'Inputs and outputs not of same unit',
  11011: 'Amountless invoice is not supported',
  11012: 'Amount in request does not equal invoice',
  11013: 'Unit in request is not supported',
  11014: 'Max inputs exceeded',
  11015: 'Max outputs exceeded',
  12001: 'Keyset is not known',
  12002: 'Keyset is inactive',
  12003: 'Keyset has expired',
  20001: 'Quote request is not paid',
  20002: 'Quote has already been issued',
  20003: 'Minting is disabled',
  20004: 'Lightning payment failed',
  20005: 'Quote is pending',
  20006: 'Invoice already paid',
  20007: 'Quote is expired',
  20008: 'Signature for mint request invalid',
  20009: 'Pubkey required for mint quote',
};

const isHex = (s: unknown, len?: number): s is string => typeof s === 'string' && /^[0-9a-f]*$/.test(s) && (len === undefined || s.length === len);

export function isPoint(hex: unknown): boolean {
  if (!isHex(hex, 66) || !/^0[23]/.test(hex)) return false;
  try {
    secp256k1.Point.fromHex(hex).assertValidity();
    return true;
  } catch {
    return false;
  }
}

/** NUT-02 keyset id, both versions, written from the spec text (not from a wallet library). */
export function keysetIdV2(keys: Record<string, string>, unit: string, fee?: number | null, finalExpiry?: number | null): string {
  const sorted = Object.entries(keys).sort((a, b) => (BigInt(a[0]) < BigInt(b[0]) ? -1 : 1));
  let pre = sorted.map(([amt, pk]) => `${amt}:${pk.toLowerCase()}`).join(',');
  pre += `|unit:${unit.toLowerCase()}`;
  if (fee) pre += `|input_fee_ppk:${fee}`;
  if (finalExpiry) pre += `|final_expiry:${finalExpiry}`;
  return '01' + bytesToHex(sha256(utf8ToBytes(pre)));
}

export function keysetIdV1(keys: Record<string, string>): string {
  const sorted = Object.entries(keys).sort((a, b) => (BigInt(a[0]) < BigInt(b[0]) ? -1 : 1));
  const bytes = sorted.map(([, pk]) => secp256k1.Point.fromHex(pk).toBytes(true));
  const all = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of bytes) {
    all.set(b, o);
    o += b.length;
  }
  return '00' + bytesToHex(sha256(all)).slice(0, 14);
}

/** A NUT-00 error body: {"detail": str, "code": int}. Returns a problem description, or null if fine. */
export function errorShape(ex: Exchange): string | null {
  if (ex.status < 400) return `HTTP ${ex.status} (expected an error)`;
  const r = ex.response as { detail?: unknown; code?: unknown };
  if (!r || typeof r !== 'object') return `HTTP ${ex.status} with a non-JSON body`;
  if (typeof r.detail !== 'string') return 'error body has no string "detail"';
  if (typeof r.code !== 'number') return 'error body has no integer "code"';
  return null;
}

const codeOf = (ex: Exchange): number | undefined => (ex.response as { code?: number })?.code;
const fmtCode = (c?: number) => (c === undefined ? 'no code' : `${c}${ERROR_CODES[c] ? ` (${ERROR_CODES[c]})` : ''}`);

/** A point nobody knows the discrete log of: a valid Y for checkstate, a fake C for swaps. */
const randomPoint = () => bytesToHex(secp256k1.getPublicKey(randomBytes(32), true));

// ---------- the free checks: no ecash needed ----------
export interface Context {
  mint: MintClient;
  info?: Record<string, any>;
  keysets?: { id: string; unit: string; active: boolean; input_fee_ppk?: number | null; final_expiry?: number | null }[];
  keys?: { id: string; unit: string; keys: Record<string, string>; input_fee_ppk?: number | null; final_expiry?: number | null }[];
}

type Check = (ctx: Context) => Promise<Omit<Result, 'id' | 'nut' | 'title' | 'exchange'>>;

interface CheckDef {
  id: string;
  nut: string;
  title: string;
  run: Check;
}

const supports = (ctx: Context, nut: string) => {
  const n = ctx.info?.nuts?.[nut];
  return !!n && (n.supported === true || Array.isArray(n.methods) || n.supported === undefined);
};


// ---------- NUT-17 websocket helper ----------
/** A JSON-RPC session on the mint's /v1/ws. Every message in and out is logged as a 'WS' exchange. */
async function wsSession(ctx: Context, timeoutMs = 8000) {
  const url = ctx.mint.url.replace(/^http/, 'ws') + '/v1/ws';
  const WS: typeof WebSocket | undefined = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
  if (!WS) throw new Error('no WebSocket in this environment');
  const ws = new WS(url);
  const inbox: any[] = [];
  const waiters: (() => void)[] = [];
  ws.onmessage = (m) => {
    let v: unknown = m.data;
    try {
      v = JSON.parse(String(m.data));
    } catch {
      /* keep text */
    }
    inbox.push(v);
    ctx.mint.log.push({ method: 'WS', path: '/v1/ws ←', status: 0, response: v });
    waiters.splice(0).forEach((w) => w());
  };
  await new Promise<void>((res, rej) => {
    const t = setTimeout(() => rej(new Error(`no websocket at ${url} within ${timeoutMs} ms`)), timeoutMs);
    ws.onopen = () => (clearTimeout(t), res());
    ws.onerror = () => (clearTimeout(t), rej(new Error(`websocket ${url} failed to open`)));
  });
  return {
    send(msg: unknown) {
      ctx.mint.log.push({ method: 'WS', path: '/v1/ws →', body: msg, status: 0, response: null });
      ws.send(JSON.stringify(msg));
    },
    /** First message (already received or arriving within the timeout) matching `pred`, removed from the inbox. */
    async next(pred: (m: any) => boolean, ms = timeoutMs): Promise<any | undefined> {
      const end = Date.now() + ms;
      for (;;) {
        const i = inbox.findIndex((m) => {
          try {
            return pred(m);
          } catch {
            return false;
          }
        });
        if (i >= 0) return inbox.splice(i, 1)[0];
        const left = end - Date.now();
        if (left <= 0) return undefined;
        await new Promise<void>((r) => {
          const t = setTimeout(r, left);
          waiters.push(() => (clearTimeout(t), r()));
        });
      }
    },
    close: () => ws.close(),
  };
}

const randId = () => Math.random().toString(36).slice(2, 10);

export const FREE_CHECKS: CheckDef[] = [
  {
    id: 'info',
    nut: '06',
    title: 'GET /v1/info answers with JSON',
    run: async (ctx) => {
      const ex = await ctx.mint.call('GET', '/v1/info');
      if (ex.status !== 200 || typeof ex.response !== 'object') return { verdict: 'fail', detail: `HTTP ${ex.status}` };
      ctx.info = ex.response as Record<string, any>;
      return { verdict: 'pass', detail: `${ctx.info.name ?? '(no name)'} · ${ctx.info.version ?? '(no version)'}` };
    },
  },
  {
    id: 'info-pubkey',
    nut: '06',
    title: 'Mint pubkey is a valid compressed secp256k1 point',
    run: async (ctx) => {
      const pk = ctx.info?.pubkey;
      if (pk === undefined) return { verdict: 'warn', detail: 'no "pubkey" field (optional, but wallets use it for NUT-23/identity)' };
      return isPoint(pk) ? { verdict: 'pass', detail: pk } : { verdict: 'fail', detail: `not a valid point: ${String(pk).slice(0, 80)}` };
    },
  },
  {
    id: 'info-nuts',
    nut: '06',
    title: 'NUT-04 and NUT-05 settings list methods and a "disabled" flag',
    run: async (ctx) => {
      const n = ctx.info?.nuts;
      if (!n || typeof n !== 'object') return { verdict: 'fail', detail: 'no "nuts" object' };
      const bad: string[] = [];
      for (const k of ['4', '5']) {
        const s = n[k];
        if (!s) bad.push(`NUT-${k} missing`);
        else {
          if (!Array.isArray(s.methods)) bad.push(`NUT-${k}.methods is not an array`);
          if (typeof s.disabled !== 'boolean') bad.push(`NUT-${k}.disabled is not a boolean`);
        }
      }
      const listed = Object.keys(n)
        .map(Number)
        .filter((x) => !Number.isNaN(x))
        .sort((a, b) => a - b);
      return bad.length ? { verdict: 'fail', detail: bad.join('; ') } : { verdict: 'pass', detail: `advertises NUT ${listed.join(', ')}` };
    },
  },
  {
    id: 'keysets',
    nut: '02',
    title: 'GET /v1/keysets lists id, unit, active (and fee)',
    run: async (ctx) => {
      const ex = await ctx.mint.call('GET', '/v1/keysets');
      const ks = (ex.response as { keysets?: unknown })?.keysets;
      if (ex.status !== 200 || !Array.isArray(ks)) return { verdict: 'fail', detail: `HTTP ${ex.status}, no keysets array` };
      ctx.keysets = ks as Context['keysets'];
      const legacy = ctx.keysets!.filter((k) => typeof k.id === 'string' && !isHex(k.id) && /^[A-Za-z0-9+/]{12}$/.test(k.id));
      const bad = ctx.keysets!.filter(
        (k) => !legacy.includes(k) && (!isHex(k.id) || typeof k.unit !== 'string' || typeof k.active !== 'boolean' || (k.input_fee_ppk != null && !(Number.isInteger(k.input_fee_ppk) && k.input_fee_ppk >= 0))),
      );
      if (bad.length) return { verdict: 'fail', detail: `${bad.length} malformed keyset(s), e.g. ${JSON.stringify(bad[0]).slice(0, 160)}` };
      const active = ctx.keysets!.filter((k) => k.active);
      if (legacy.some((k) => k.active)) return { verdict: 'fail', detail: 'an ACTIVE keyset still has a legacy base64 id' };
      return {
        verdict: !active.length ? 'fail' : legacy.length ? 'warn' : 'pass',
        detail: `${ctx.keysets!.length} keysets, ${active.length} active (${active.map((k) => `${k.unit}${k.input_fee_ppk ? ` fee ${k.input_fee_ppk}ppk` : ''}`).join(', ')})${legacy.length ? `; ${legacy.length} inactive keyset(s) still listed with pre-V1 base64 ids` : ''}`,
      };
    },
  },
  {
    id: 'keys',
    nut: '01',
    title: 'GET /v1/keys serves the active keysets, every key a valid point',
    run: async (ctx) => {
      const ex = await ctx.mint.call('GET', '/v1/keys');
      const ks = (ex.response as { keysets?: unknown })?.keysets;
      if (ex.status !== 200 || !Array.isArray(ks)) return { verdict: 'fail', detail: `HTTP ${ex.status}, no keysets array` };
      ctx.keys = ks as Context['keys'];
      const problems: string[] = [];
      for (const k of ctx.keys!) {
        const entries = Object.entries(k.keys ?? {});
        if (!entries.length) problems.push(`${k.id}: no keys`);
        const badPts = entries.filter(([, pk]) => !isPoint(pk));
        if (badPts.length) problems.push(`${k.id}: ${badPts.length} invalid point(s)`);
        const badAmts = entries.filter(([a]) => !/^\d+$/.test(a) || BigInt(a) <= 0n);
        if (badAmts.length) problems.push(`${k.id}: amounts not positive integers`);
      }
      const inactive = ctx.keys!.filter((k) => ctx.keysets?.find((s) => s.id === k.id)?.active === false);
      if (inactive.length) problems.push(`serves ${inactive.length} inactive keyset(s); NUT-01 says /v1/keys returns active keysets only`);
      return problems.length ? { verdict: 'fail', detail: problems.join('; ') } : { verdict: 'pass', detail: `${ctx.keys!.length} keysets, ${ctx.keys!.reduce((n, k) => n + Object.keys(k.keys).length, 0)} keys` };
    },
  },
  {
    id: 'keyset-ids',
    nut: '02',
    title: 'Keyset ids derive from the keys (V1/V2 rules)',
    run: async (ctx) => {
      if (!ctx.keys?.length) return { verdict: 'skip', detail: 'no keys' };
      const lines: string[] = [];
      let fail = 0;
      for (const k of ctx.keys) {
        const meta = ctx.keysets?.find((s) => s.id === k.id);
        const fee = meta?.input_fee_ppk ?? k.input_fee_ppk;
        const exp = meta?.final_expiry ?? k.final_expiry;
        let want: string;
        if (k.id.startsWith('01')) want = keysetIdV2(k.keys, k.unit, fee, exp);
        else if (k.id.startsWith('00')) want = keysetIdV1(k.keys);
        else {
          lines.push(`${k.id}: unknown version byte`);
          fail++;
          continue;
        }
        if (want !== k.id) {
          fail++;
          lines.push(`${k.id.slice(0, 18)}… derives to ${want.slice(0, 18)}…`);
        }
      }
      return fail ? { verdict: 'fail', detail: lines.join('; ') } : { verdict: 'pass', detail: `${ctx.keys.length} of ${ctx.keys.length} ids match` };
    },
  },
  {
    id: 'keys-by-id',
    nut: '01',
    title: 'GET /v1/keys/{id} returns the same keys',
    run: async (ctx) => {
      const k = ctx.keys?.[0];
      if (!k) return { verdict: 'skip', detail: 'no keys' };
      const ex = await ctx.mint.call('GET', `/v1/keys/${k.id}`);
      const got = (ex.response as { keysets?: { id: string; keys: Record<string, string> }[] })?.keysets?.[0];
      if (ex.status !== 200 || !got) return { verdict: 'fail', detail: `HTTP ${ex.status}` };
      const same = got.id === k.id && JSON.stringify(Object.entries(got.keys).sort()) === JSON.stringify(Object.entries(k.keys).sort());
      return same ? { verdict: 'pass', detail: k.id } : { verdict: 'fail', detail: 'different keys for the same id' };
    },
  },
  {
    id: 'keys-unknown',
    nut: '02',
    title: 'Unknown keyset id is refused with code 12001',
    run: async (ctx) => {
      const ex = await ctx.mint.call('GET', `/v1/keys/01${'ab'.repeat(32)}`);
      if (ex.status === 200) return { verdict: 'fail', detail: 'HTTP 200 for a keyset that does not exist' };
      const shape = errorShape(ex);
      if (shape) return { verdict: 'warn', detail: `HTTP ${ex.status}: ${shape}` };
      return codeOf(ex) === 12001 ? { verdict: 'pass', detail: fmtCode(12001) } : { verdict: 'warn', detail: `code ${fmtCode(codeOf(ex))}, spec says 12001` };
    },
  },
  {
    id: 'checkstate-unknown',
    nut: '07',
    title: 'POST /v1/checkstate: a never-seen Y is UNSPENT',
    run: async (ctx) => {
      if (!supports(ctx, '7')) return { verdict: 'skip', detail: 'NUT-07 not advertised' };
      const Y = randomPoint();
      const ex = await ctx.mint.call('POST', '/v1/checkstate', { Ys: [Y] });
      const st = (ex.response as { states?: { Y: string; state: string; witness?: unknown }[] })?.states;
      if (ex.status !== 200 || !Array.isArray(st)) return { verdict: 'fail', detail: `HTTP ${ex.status}` };
      if (st.length !== 1 || st[0].Y !== Y) return { verdict: 'fail', detail: 'states do not echo the Y asked for' };
      return st[0].state === 'UNSPENT' ? { verdict: 'pass', detail: 'UNSPENT' } : { verdict: 'fail', detail: `state ${st[0].state}` };
    },
  },
  {
    id: 'checkstate-order',
    nut: '07',
    title: 'checkstate answers in the order asked',
    run: async (ctx) => {
      if (!supports(ctx, '7')) return { verdict: 'skip', detail: 'NUT-07 not advertised' };
      const Ys = [randomPoint(), randomPoint(), randomPoint()];
      const ex = await ctx.mint.call('POST', '/v1/checkstate', { Ys });
      const st = (ex.response as { states?: { Y: string }[] })?.states;
      if (!Array.isArray(st)) return { verdict: 'fail', detail: `HTTP ${ex.status}` };
      return st.map((s) => s.Y).join() === Ys.join() ? { verdict: 'pass', detail: '3 of 3 in order' } : { verdict: 'fail', detail: 'order differs' };
    },
  },
  {
    id: 'swap-forged',
    nut: '03',
    title: 'Swap with a forged proof is refused (10001)',
    run: async (ctx) => {
      const ks = ctx.keysets?.find((k) => k.active && k.unit === 'sat') ?? ctx.keysets?.find((k) => k.active);
      if (!ks) return { verdict: 'skip', detail: 'no active keyset' };
      const secret = bytesToHex(randomBytes(32));
      const ex = await ctx.mint.call('POST', '/v1/swap', {
        inputs: [{ amount: 8, id: ks.id, secret, C: randomPoint() }],
        outputs: [{ amount: 8, id: ks.id, B_: randomPoint() }],
      });
      if (ex.status === 200) return { verdict: 'fail', detail: 'the mint SIGNED outputs for a forged proof' };
      const shape = errorShape(ex);
      if (shape) return { verdict: 'warn', detail: `refused, but ${shape}` };
      const c = codeOf(ex);
      // An unbalanced fee could be reported first on fee-charging mints; both are refusals.
      return c === 10001 ? { verdict: 'pass', detail: fmtCode(c) } : { verdict: 'warn', detail: `refused with ${fmtCode(c)}; spec code for a bad signature is 10001` };
    },
  },
  {
    id: 'swap-unbalanced',
    nut: '03',
    title: 'Error bodies follow NUT-00 {detail, code}',
    run: async (ctx) => {
      const ex = await ctx.mint.call('POST', '/v1/swap', { inputs: [], outputs: [] });
      if (ex.status === 200) return { verdict: 'warn', detail: 'an empty swap returned HTTP 200' };
      const shape = errorShape(ex);
      return shape ? { verdict: 'fail', detail: shape } : { verdict: 'pass', detail: `HTTP ${ex.status}, ${fmtCode(codeOf(ex))}` };
    },
  },
  {
    id: 'mint-quote',
    nut: '04',
    title: 'Mint quote (bolt11): quote, request, state, expiry; GET returns it',
    run: async (ctx) => {
      if (!ctx.info?.nuts?.['4']?.methods?.some((m: { method: string }) => m.method === 'bolt11')) return { verdict: 'skip', detail: 'bolt11 minting not advertised' };
      if (ctx.info.nuts['4'].disabled) return { verdict: 'skip', detail: 'minting disabled' };
      const unit = ctx.keysets?.find((k) => k.active && k.unit === 'sat')?.unit ?? ctx.keysets?.find((k) => k.active)?.unit ?? 'sat';
      const m = ctx.info.nuts['4'].methods.find((x: { method: string; unit?: string }) => x.method === 'bolt11' && x.unit === unit);
      const amount = Math.max(unit === 'sat' ? 1 : 100, Number(m?.min_amount ?? 0));
      const ex = await ctx.mint.call('POST', '/v1/mint/quote/bolt11', { amount, unit });
      const q = ex.response as { quote?: string; request?: string; state?: string; expiry?: number | null; amount?: number; unit?: string };
      if (ex.status !== 200) {
        const c = codeOf(ex);
        if (c === 11006) return { verdict: 'info', detail: `${amount} ${unit} is outside the limits (11006)` };
        const why = String((ex.response as { detail?: string })?.detail ?? '').slice(0, 100);
        return { verdict: 'fail', detail: `advertises bolt11 minting but refused a quote: HTTP ${ex.status} ${fmtCode(c)}${why ? ` "${why}"` : ''}` };
      }
      const bad: string[] = [];
      if (typeof q.quote !== 'string') bad.push('no quote id');
      if (typeof q.request !== 'string' || !/^ln(bc|tb|bcrt|tbs)/i.test(q.request)) bad.push('request is not a bolt11 invoice');
      if (q.state !== 'UNPAID' && q.state !== 'PAID') bad.push(`state "${q.state}"`);
      if (!('expiry' in q)) bad.push('no expiry field');
      if (bad.length) return { verdict: 'fail', detail: bad.join('; ') };
      const ex2 = await ctx.mint.call('GET', `/v1/mint/quote/bolt11/${q.quote}`);
      const q2 = ex2.response as typeof q;
      if (ex2.status !== 200 || q2.quote !== q.quote || q2.request !== q.request) return { verdict: 'fail', detail: 'GET by id does not return the same quote' };
      return { verdict: 'pass', detail: `${amount} ${unit}: state ${q.state}${q.state === 'PAID' ? ' (test mint: pays itself)' : ''}` };
    },
  },
  {
    id: 'melt-garbage',
    nut: '05',
    title: 'Melt quote for a non-invoice is refused with a NUT-00 error',
    run: async (ctx) => {
      if (!ctx.info?.nuts?.['5']?.methods?.some((m: { method: string }) => m.method === 'bolt11')) return { verdict: 'skip', detail: 'bolt11 melting not advertised' };
      const ex = await ctx.mint.call('POST', '/v1/melt/quote/bolt11', { request: 'lnbc1notaninvoice', unit: 'sat' });
      if (ex.status === 200) return { verdict: 'fail', detail: 'accepted a malformed invoice' };
      const shape = errorShape(ex);
      return shape ? { verdict: 'warn', detail: `refused, but ${shape}` } : { verdict: 'pass', detail: `${fmtCode(codeOf(ex))}: ${String((ex.response as { detail: string }).detail).slice(0, 80)}` };
    },
  },
  {
    id: 'restore-unknown',
    nut: '09',
    title: 'Restore of a never-signed output returns nothing',
    run: async (ctx) => {
      if (!supports(ctx, '9')) return { verdict: 'skip', detail: 'NUT-09 not advertised' };
      const ks = ctx.keysets?.find((k) => k.active);
      if (!ks) return { verdict: 'skip', detail: 'no active keyset' };
      const ex = await ctx.mint.call('POST', '/v1/restore', { outputs: [{ amount: 1, id: ks.id, B_: randomPoint() }] });
      const r = ex.response as { outputs?: unknown[]; signatures?: unknown[] };
      if (ex.status !== 200) return { verdict: 'fail', detail: `HTTP ${ex.status} ${fmtCode(codeOf(ex))}` };
      return Array.isArray(r.outputs) && Array.isArray(r.signatures) && !r.outputs.length && !r.signatures.length
        ? { verdict: 'pass', detail: 'empty outputs and signatures' }
        : { verdict: 'fail', detail: JSON.stringify(r).slice(0, 120) };
    },
  },
  {
    id: 'ws-subscribe',
    nut: '17',
    title: 'WebSocket: subscribe to a mint quote and a proof state, get the current state at once, unsubscribe',
    run: async (ctx) => {
      const n17 = ctx.info?.nuts?.['17'];
      if (!n17) return { verdict: 'skip', detail: 'NUT-17 not advertised' };
      const sup = n17.supported;
      if (!Array.isArray(sup) || !sup.every((x: any) => typeof x?.method === 'string' && typeof x?.unit === 'string' && Array.isArray(x?.commands)))
        return { verdict: 'fail', detail: 'nuts.17.supported is not a list of { method, unit, commands }' };
      const cmds = new Set<string>(sup.flatMap((x: any) => x.commands));
      const n4 = ctx.info?.nuts?.['4'];
      const canQuote = cmds.has('bolt11_mint_quote') && !n4?.disabled && n4?.methods?.some((m: { method: string; unit?: string }) => m.method === 'bolt11' && m.unit === 'sat');
      if (!canQuote && !cmds.has('proof_state')) return { verdict: 'skip', detail: `commands: ${[...cmds].join(', ')}` };
      const s = await wsSession(ctx);
      const got: string[] = [];
      const bad: string[] = [];
      try {
        const subs: { kind: string; filter: string; ok: (p: any) => boolean; subId: string }[] = [];
        if (canQuote) {
          const ex = await ctx.mint.call('POST', '/v1/mint/quote/bolt11', { amount: 1, unit: 'sat' });
          const q = (ex.response as { quote?: string })?.quote;
          if (ex.status === 200 && q) subs.push({ kind: 'bolt11_mint_quote', filter: q, subId: randId(), ok: (p) => p?.quote === q && ['UNPAID', 'PAID', 'ISSUED'].includes(p?.state) });
        }
        if (cmds.has('proof_state')) {
          const Y = randomPoint();
          subs.push({ kind: 'proof_state', filter: Y, subId: randId(), ok: (p) => p?.Y === Y && p?.state === 'UNSPENT' });
        }
        if (!subs.length) return { verdict: 'skip', detail: 'could not get a quote to subscribe to' };
        let rpcId = 0;
        for (const sub of subs) {
          const id = rpcId++;
          s.send({ jsonrpc: '2.0', method: 'subscribe', params: { kind: sub.kind, subId: sub.subId, filters: [sub.filter] }, id });
          const ack = await s.next((m) => m.id === id);
          if (!ack) bad.push(`${sub.kind}: no reply to subscribe`);
          else if (ack.error) bad.push(`${sub.kind}: subscribe refused (${JSON.stringify(ack.error).slice(0, 80)})`);
          else if (ack.result?.status !== 'OK' || ack.result?.subId !== sub.subId) bad.push(`${sub.kind}: reply is not { status: "OK", subId }`);
          const note = await s.next((m) => m.method === 'subscribe' && m.params?.subId === sub.subId, 5000);
          if (!note)
            bad.push(sub.kind === 'proof_state'
              ? 'proof_state: no current-state notification for a proof the mint never saw (NUT-07 calls it UNSPENT; NUT-17: the mint MUST first send the current state)'
              : `${sub.kind}: no notification with the current state`);
          else if (!sub.ok(note.params.payload)) bad.push(`${sub.kind}: unexpected payload ${JSON.stringify(note.params.payload).slice(0, 80)}`);
          else got.push(`${sub.kind} → ${note.params.payload.state}`);
        }
        // unsubscribe the first one; then an unknown kind must be refused with a JSON-RPC error
        const uid = rpcId++;
        s.send({ jsonrpc: '2.0', method: 'unsubscribe', params: { subId: subs[0].subId }, id: uid });
        const uack = await s.next((m) => m.id === uid);
        if (!uack || uack.error || uack.result?.status !== 'OK') bad.push(`unsubscribe: ${uack ? JSON.stringify(uack.error ?? uack.result).slice(0, 80) : 'no reply'}`);
        const eid = rpcId++;
        s.send({ jsonrpc: '2.0', method: 'subscribe', params: { kind: 'no_such_kind', subId: randId(), filters: ['x'] }, id: eid });
        const eack = await s.next((m) => m.id === eid);
        if (!eack) bad.push('unknown kind: no reply');
        else if (!eack.error) bad.push('unknown kind accepted');
      } finally {
        s.close();
      }
      if (bad.length) return { verdict: got.length ? 'warn' : 'fail', detail: [...got, ...bad].join('; ') };
      return { verdict: 'pass', detail: `${got.join(', ')}; unsubscribe OK; unknown kind refused` };
    },
  },
];

export interface Report {
  mint: string;
  at: number;
  results: Result[];
}

/** Run the checks in order (later ones read what earlier ones learned). */
export async function runChecks(mint: MintClient, defs: CheckDef[] = FREE_CHECKS, onResult?: (r: Result) => void, ctx: Context = { mint }): Promise<Report> {
  const results: Result[] = [];
  for (const d of defs) {
    const before = mint.log.length;
    let r: Result;
    try {
      const out = await d.run(ctx);
      r = { id: d.id, nut: d.nut, title: d.title, ...out };
    } catch (e) {
      const msg = e instanceof Error ? (e.name === 'AbortError' ? 'timed out' : e.message) : String(e);
      r = { id: d.id, nut: d.nut, title: d.title, verdict: 'fail', detail: `request failed: ${msg}` };
    }
    r.exchange = mint.log.slice(before);
    results.push(r);
    onResult?.(r);
    if (d.id === 'info' && r.verdict === 'fail') break; // nothing else will work
  }
  return { mint: mint.url, at: Math.floor(Date.now() / 1000), results };
}
