# 🔬 Nutcheck — does your Cashu mint speak the NUTs?

**Live: https://mmajjd926-netizen.github.io/nutcheck/**

Paste a mint URL, get a conformance report. Each check is written from the text of the
[NUT specs](https://github.com/cashubtc/nuts), talks to the mint over plain HTTP from your browser and
shows the exact request and response, so a mint operator (or a wallet developer chasing a bug) can see
*why* something fails, not just that it does.

![A report](docs/report.png)

## What it checks (no ecash needed)

| NUT | Check |
|---|---|
| 06 | `/v1/info` answers; `pubkey` is a valid compressed secp256k1 point; NUT-04/05 settings have `methods` and `disabled` |
| 02 | `/v1/keysets` entries have `id`, `unit`, `active`, a non-negative integer `input_fee_ppk`; legacy base64 ids flagged |
| 01 | `/v1/keys` serves only active keysets, every key a valid point, amounts positive integers; `/v1/keys/{id}` agrees |
| 02 | **Keyset ids re-derived from the keys** (V2: `amount:pubkey,…|unit:…|input_fee_ppk:…|final_expiry:…`, V1: first 7 bytes of the hash), implemented independently of any wallet library |
| 02 | Unknown keyset id → error `12001` |
| 07 | `checkstate` of a never-seen `Y` is `UNSPENT`, answers in the order asked |
| 03 | A swap with a forged proof is refused with `10001`, never signed; error bodies are `{detail, code}` |
| 04 | A bolt11 mint quote has `quote`, a bolt11 `request`, `state`, `expiry`; GET by id returns it (unit and minimum taken from the mint's own settings) |
| 05 | A melt quote for a non-invoice is refused with a NUT-00 error |
| 09 | Restoring a never-signed blinded message returns empty `outputs`/`signatures` |

The random points used as fake `Y`, `C` and `B_` are fresh public keys, so nobody knows their discrete log.

## Public mints today

`tools/matrix.mjs` runs the same checks from a server against public mints and writes `public/matrix.json`,
shown under the form. First run (22 Nov 2026, 14 reachable mints, Nutshell 0.17–0.22, CDK 0.17–0.18):

- Every reachable mint derives its keyset ids correctly and refuses forged proofs.
- `mint.agorist.space` (Nutshell 0.17.0) advertises bolt11 minting but cannot create an invoice
  (`20000 could not fetch bolt11 payment request from backend`), and still answers forged proofs with the
  old code `10003` instead of `10001`.
- `8333.space:3338` still lists two inactive keysets with pre-V1 base64 ids.
- Nutshell answers generic errors with `code: 0`, CDK with `50000`; neither is in the error table.

## Run it

```
npm install
npm run dev                                   # the web page
NUTCHECK_LIVE=1 npx vitest run                # checks against testnut and Minibits, printed
node --experimental-strip-types tools/matrix.mjs   # refresh public/matrix.json
```

Made for [Nut November](https://nutnovember.org/) 2026. MIT.
