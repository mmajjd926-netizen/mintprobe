import './style.css';
import { FREE_CHECKS, MintClient, runChecks, type Report, type Result, type Verdict } from './checks';

const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const $ = <T extends HTMLElement = HTMLElement>(s: string) => document.querySelector<T>(s)!;
const ICON: Record<Verdict, string> = { pass: '✓', fail: '✗', warn: '!', skip: '–', info: 'i' };

function row(r: Result): string {
  const ex = (r.exchange ?? [])
    .map(
      (e) => `<div class="ex"><div class="req"><b>${esc(e.method)}</b> ${esc(e.path)}${e.body !== undefined ? `<pre>${esc(JSON.stringify(e.body, null, 1))}</pre>` : ''}</div>
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
    const rep = await runChecks(new MintClient(url), FREE_CHECKS, (r) => rows.insertAdjacentHTML('beforeend', row(r)));
    rows.insertAdjacentHTML('beforebegin', summary(rep));
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
    const ids = FREE_CHECKS.map((c) => c.id);
    $('#known').innerHTML = data.reports.map((r) => `<option value="${esc(r.mint)}"></option>`).join('');
    const head = FREE_CHECKS.map((c) => `<th title="NUT-${esc(c.nut)}: ${esc(c.title)}"><span>${esc(c.nut)}</span></th>`).join('');
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
      <p class="note">Free checks only (no ecash moved), run from a server on ${new Date(data.generated * 1000).toUTCString()}. Hover a cell for details; click a mint to run it live from your browser.</p>
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
