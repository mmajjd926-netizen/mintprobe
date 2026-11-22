import './style.css';
import { getEncodedToken } from '@cashu/cashu-ts';
import { FREE_CHECKS, MintClient, runChecks, type Report, type Result, type Verdict } from './checks';
import { FUNDED_CHECKS, runFunded, type FundedContext } from './funded';

const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const $ = <T extends HTMLElement = HTMLElement>(s: string) => document.querySelector<T>(s)!;
const ICON: Record<Verdict, string> = { pass: '✓', fail: '✗', warn: '!', skip: '–', info: 'i' };

function row(r: Result): string {
  const ex = (r.exchange ?? [])
    .map((e) =>
      e.method === 'WS'
        ? `<div class="ex"><div class="req"><b>WS</b> ${esc(e.path)}<pre>${esc(JSON.stringify(e.body ?? e.response, null, 1).slice(0, 4000))}</pre></div></div>`
        : `<div class="ex"><div class="req"><b>${esc(e.method)}</b> ${esc(e.path)}${e.body !== undefined ? `<pre>${esc(JSON.stringify(e.body, null, 1))}</pre>` : ''}</div>
      <div class="res"><b>HTTP ${e.status}</b><pre>${esc(typeof e.response === 'string' ? e.response.slice(0, 2000) : JSON.stringify(e.response, null, 1).slice(0, 4000))}</pre></div></div>`,
    )
    .join('');
  return `<details class="check ${r.verdict}">
    <summary><span class="v">${ICON[r.verdict]}</span><span class="nut">NUT-${esc(r.nut)}</span><span class="t">${esc(r.title)}</span><span class="d">${esc(r.detail)}</span></summary>
    ${ex || '<p class="note">No request (decided from earlier answers).</p>'}
  </details>`;
}

function summary(rep: Report): string {
  const n = (v: Verdict) => rep.results.filter((r) => r.verdict === v).length;
  return `<div class="sum"><span class="pass">${n('pass')} pass</span><span class="fail">${n('fail')} fail</span><span class="warn">${n('warn')} warn</span><span class="skip">${n('skip')} skipped</span></div>`;
}

async function run(url: string) {
  const btn = $<HTMLButtonElement>('#go');
  btn.disabled = true;
  $('#note').textContent = '';
  const box = $('#report');
  box.innerHTML = `<h2>${esc(url)}</h2><div id="rows"></div>`;
  const rows = $('#rows');
  try {
    const mint = new MintClient(url);
    const ctx: FundedContext = { mint };
    const rep = await runChecks(mint, FREE_CHECKS, (r) => rows.insertAdjacentHTML('beforeend', row(r)), ctx);
    rows.insertAdjacentHTML('beforebegin', summary(rep));
    if (rep.results[0]?.verdict === 'pass') {
      rows.insertAdjacentHTML(
        'afterend',
        `<div id="funded"><h2>With ecash</h2><p class="note">Mints 100 sat and spends it: DLEQ (NUT-12), exact fees, double spend, SPENT state, P2PK (NUT-11), HTLC and its refund (NUT-14).
        Test mints pay their own invoice; on a real mint you pay 100 sat and get back what is left (about 85 sat) as a token at the end.</p>
        <button id="fund-go">Run with ecash</button><div id="invoice"></div><div id="frows"></div><div id="left"></div></div>`,
      );
      $('#fund-go').addEventListener('click', async () => {
        const b = $<HTMLButtonElement>('#fund-go');
        b.disabled = true;
        ctx.waitMs = 10 * 60_000;
        ctx.pay = (inv) => {
          $('#invoice').innerHTML = `<p class="note">Pay this invoice (100 sat) from any Lightning wallet. Waiting up to 10 minutes…</p><pre class="inv">${esc(inv)}</pre>`;
        };
        try {
          await runFunded(ctx, (r) => {
            $('#invoice').innerHTML = '';
            $('#frows').insertAdjacentHTML('beforeend', row(r));
          });
          const left = ctx.funded?.pool ?? [];
          if (left.length && !/testnut/.test(url)) {
            const t = getEncodedToken({ mint: url, proofs: left });
            $('#left').innerHTML = `<p class="note">What is left, as a Cashu token (paste it into any wallet):</p><pre class="inv">${esc(t)}</pre>`;
          }
        } finally {
          b.remove();
        }
      });
    }
    const first = rep.results[0];
    if (first?.verdict === 'fail' && /fetch|NetworkError|Failed/i.test(first.detail))
      $('#note').textContent = 'The browser could not reach the mint. Either it is down or it does not send CORS headers (then no web wallet can use it either).';
    history.replaceState(null, '', `#${encodeURIComponent(url)}`);
  } finally {
    btn.disabled = false;
  }
}

$('#run').addEventListener('submit', (e) => {
  e.preventDefault();
  run($<HTMLInputElement>('#url').value.trim());
});

async function matrix() {
  const box = $('#matrix');
  try {
    const data: { generated: number; reports: Report[] } = await (await fetch('./matrix.json')).json();
    const all = [...FREE_CHECKS, ...FUNDED_CHECKS];
    const ids = all.map((c) => c.id);
    $('#known').innerHTML = data.reports.map((r) => `<option value="${esc(r.mint)}"></option>`).join('');
    const head = all.map((c, i) => `<th class="${i === FREE_CHECKS.length ? 'sep' : ''}" title="NUT-${esc(c.nut)}: ${esc(c.title)}"><span>${esc(c.nut)}</span></th>`).join('');
    const body = data.reports
      .map((r) => {
        const impl = r.results[0]?.detail.split(' · ')[1] ?? '';
        const cells = ids
          .map((id) => {
            const x = r.results.find((y) => y.id === id);
            return x ? `<td class="${x.verdict}" title="${esc(x.title)}: ${esc(x.detail)}">${ICON[x.verdict]}</td>` : '<td></td>';
          })
          .join('');
        return `<tr><th class="m"><a href="#${esc(encodeURIComponent(r.mint))}" data-m="${esc(r.mint)}">${esc(r.mint.replace(/^https:\/\//, ''))}</a><small>${esc(impl)}</small></th>${cells}</tr>`;
      })
      .join('');
    box.innerHTML = `<h2>Public mints today</h2>
      <p class="note">Free checks for every mint; the columns after the divider move ecash and only run on test mints that pay their own invoices. Run from a server on ${new Date(data.generated * 1000).toUTCString()}. Hover a cell for details; click a mint to run it live from your browser.</p>
      <div class="scroll"><table class="mx"><thead><tr><th></th>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
    box.querySelectorAll<HTMLAnchorElement>('a[data-m]').forEach((a) =>
      a.addEventListener('click', (e) => {
        e.preventDefault();
        $<HTMLInputElement>('#url').value = a.dataset.m!;
        window.scrollTo({ top: 0, behavior: 'smooth' });
        run(a.dataset.m!);
      }),
    );
  } catch {
    box.innerHTML = '';
  }
}

matrix();
const fromHash = decodeURIComponent(location.hash.slice(1));
if (/^https?:\/\//.test(fromHash)) {
  $<HTMLInputElement>('#url').value = fromHash;
  run(fromHash);
}
