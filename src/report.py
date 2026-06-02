"""
FirmwareGuard — HTML Report Generator  (v1.1)
Self-contained report with clickable findings that open a rich detail modal.
"""

import json
from datetime import datetime
from collections import Counter


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}
SEV_COLOR = {
    "CRITICAL": ("#b71c1c", "#ffcdd2", "🔴"),
    "HIGH":     ("#c62828", "#ffebee", "🟠"),
    "MEDIUM":   ("#e65100", "#fff3e0", "🟡"),
    "LOW":      ("#f57f17", "#fffde7", "🔵"),
    "INFO":     ("#37474f", "#eceff1", "ℹ️"),
    "OK":       ("#1b5e20", "#e8f5e9", "✅"),
}


class ReportGenerator:
    def generate(self, filepath: str, findings: list, meta: dict) -> str:
        sorted_findings = sorted(
            findings,
            key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99)
        )
        counts      = Counter(f.get("severity", "INFO") for f in findings)
        risk_score  = self._risk_score(counts)
        risk_label, risk_color = self._risk_label(risk_score)
        categories  = {}
        for f in sorted_findings:
            categories.setdefault(f.get("category", "General"), []).append(f)

        modal_data = []
        for f in sorted_findings:
            modal_data.append({
                "severity":    f.get("severity", "INFO"),
                "category":    f.get("category", ""),
                "title":       f.get("title", ""),
                "detail":      f.get("detail", ""),
                "description": f.get("description", ""),
                "impact":      f.get("impact", ""),
                "remediation": f.get("remediation", ""),
                "references":  f.get("references", []),
                "cvss":        f.get("cvss", ""),
            })

        findings_json = json.dumps(modal_data, ensure_ascii=False)
        return self._render(meta, sorted_findings, counts, risk_score,
                            risk_label, risk_color, categories, findings_json)

    def _risk_score(self, counts):
        return min(counts.get("CRITICAL", 0)*40 + counts.get("HIGH", 0)*15
                   + counts.get("MEDIUM", 0)*5 + counts.get("LOW", 0)*1, 100)

    def _risk_label(self, score):
        if score >= 60: return "CRITICAL RISK",  "#b71c1c"
        if score >= 35: return "HIGH RISK",       "#c62828"
        if score >= 15: return "MEDIUM RISK",     "#e65100"
        if score >=  5: return "LOW RISK",        "#f57f17"
        return "MINIMAL RISK", "#2e7d32"

    def _render(self, meta, findings, counts, score, risk_label,
                risk_color, cats, findings_json):
        rows_html = self._rows(findings)
        cats_html = self._category_cards(cats)
        total     = len(findings)
        scan_time = meta.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        def c(k): return counts.get(k, 0)

        # We use .format() carefully by escaping all braces in JS/CSS
        html = self._template()
        return html.format(
            filename    = self._esc(meta.get('filename','N/A')),
            size        = self._esc(meta.get('size_human','N/A')),
            ftype       = self._esc(meta.get('detected_type','N/A')),
            entropy     = self._esc(str(meta.get('entropy','N/A'))),
            scan_time   = self._esc(scan_time),
            sha256      = self._esc(meta.get('sha256','N/A')),
            sha256_short= self._esc(meta.get('sha256','N/A')[:24]),
            n_critical  = c('CRITICAL'),
            n_high      = c('HIGH'),
            n_medium    = c('MEDIUM'),
            n_low       = c('LOW'),
            n_info      = c('INFO'),
            n_ok        = c('OK'),
            n_total     = total,
            risk_score  = score,
            arc_dash    = int(score * 3.14),
            risk_color  = risk_color,
            risk_label  = risk_label,
            cats_html   = cats_html,
            rows_html   = rows_html,
            findings_json = findings_json,
        )

    def _template(self):
        return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FirmwareGuard Security Report</title>
<style>
:root{{--bg:#0f1117;--surface:#1a1d27;--surface2:#22263a;--surface3:#2a2f47;--accent:#1e88e5;--text:#e8eaf6;--dim:#7986cb;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;}}
.header{{background:linear-gradient(135deg,#0d1321 0%,#1a237e 100%);padding:36px 48px 28px;border-bottom:3px solid var(--accent);}}
.header-inner{{max-width:1200px;margin:0 auto;}}
.brand{{display:flex;align-items:center;gap:14px;margin-bottom:16px;}}
.brand-icon{{font-size:2.2rem;}}
.brand-name{{font-size:1.8rem;font-weight:800;}}
.brand-sub{{font-size:.88rem;color:#9fa8da;}}
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(195px,1fr));gap:10px;margin-top:16px;}}
.meta-item{{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:11px 15px;}}
.meta-label{{font-size:.72rem;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;}}
.meta-value{{font-size:.88rem;font-weight:600;word-break:break-all;font-family:Consolas,monospace;margin-top:2px;}}
.main{{max-width:1200px;margin:0 auto;padding:28px 48px;}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:12px;margin-bottom:24px;}}
.sev-card{{background:var(--surface);border-radius:12px;padding:16px;text-align:center;border-top:3px solid var(--c);transition:transform .15s;}}
.sev-card:hover{{transform:translateY(-3px);}}
.sev-count{{font-size:2.2rem;font-weight:800;color:var(--c);line-height:1;}}
.sev-label{{font-size:.74rem;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px;}}
.gauge-row{{display:flex;align-items:center;gap:26px;background:var(--surface);border-radius:14px;padding:22px 26px;margin-bottom:24px;}}
.gauge-wrap{{position:relative;width:100px;height:100px;flex-shrink:0;}}
.gauge-svg{{transform:rotate(-90deg);}}
.gauge-bg{{fill:none;stroke:var(--surface2);stroke-width:10;}}
.gauge-arc{{fill:none;stroke:{risk_color};stroke-width:10;stroke-linecap:round;stroke-dasharray:{arc_dash} 314;}}
.gauge-text{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}}
.gauge-score{{font-size:1.5rem;font-weight:800;color:{risk_color};}}
.gauge-unit{{font-size:.62rem;color:var(--dim);}}
.risk-info h2{{font-size:1.2rem;font-weight:700;color:{risk_color};}}
.risk-info p{{color:var(--dim);font-size:.88rem;margin-top:4px;}}
.section-title{{font-size:1rem;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.07em;margin:22px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--surface2);}}
.cat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px;margin-bottom:24px;}}
.cat-card{{background:var(--surface);border-radius:10px;padding:14px 16px;border-left:4px solid var(--accent);}}
.cat-card h3{{font-size:.92rem;font-weight:700;margin-bottom:6px;}}
.cat-badge{{display:inline-block;font-size:.7rem;font-weight:600;padding:2px 7px;border-radius:99px;margin-right:3px;margin-bottom:3px;}}
.findings-wrap{{background:var(--surface);border-radius:12px;overflow:hidden;margin-bottom:24px;}}
.findings-wrap table{{width:100%;border-collapse:collapse;font-size:.875rem;}}
thead th{{background:var(--surface2);color:var(--dim);font-size:.73rem;text-transform:uppercase;letter-spacing:.07em;padding:11px 13px;text-align:left;font-weight:600;}}
tbody tr{{border-bottom:1px solid rgba(255,255,255,.05);cursor:pointer;transition:background .1s;}}
tbody tr:hover{{background:rgba(30,136,229,.13)!important;}}
tbody td{{padding:9px 13px;vertical-align:top;}}
.sev-pill{{display:inline-block;font-size:.7rem;font-weight:700;padding:2px 8px;border-radius:99px;}}
.detail-text{{font-family:Consolas,monospace;font-size:.78rem;color:var(--dim);word-break:break-all;}}
.click-hint{{font-size:.68rem;color:var(--accent);opacity:.7;}}
.filter-bar{{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:10px;}}
.filter-btn{{background:var(--surface2);border:1px solid rgba(255,255,255,.1);color:var(--text);padding:4px 13px;border-radius:99px;font-size:.78rem;cursor:pointer;transition:all .15s;}}
.filter-btn:hover,.filter-btn.active{{background:var(--accent);border-color:var(--accent);color:#fff;}}
input.search-box{{background:var(--surface);border:1px solid rgba(255,255,255,.1);color:var(--text);padding:7px 13px;border-radius:8px;font-size:.84rem;outline:none;width:100%;margin-bottom:10px;}}
input.search-box:focus{{border-color:var(--accent);}}
/* modal */
.modal-backdrop{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.78);z-index:1000;align-items:center;justify-content:center;}}
.modal-backdrop.open{{display:flex;}}
.modal{{background:var(--surface);border-radius:14px;width:min(840px,96vw);max-height:90vh;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,.75);overflow:hidden;animation:mIn .18s ease;}}
@keyframes mIn{{from{{transform:scale(.94);opacity:0;}}to{{transform:scale(1);opacity:1;}}}}
.modal-bar{{height:5px;flex-shrink:0;}}
.modal-header{{background:var(--surface2);padding:16px 22px;flex-shrink:0;}}
.modal-pill{{display:inline-block;font-size:.78rem;font-weight:700;padding:3px 11px;border-radius:99px;color:#fff;margin-bottom:7px;}}
.modal-cat{{font-size:.8rem;color:var(--dim);margin-left:8px;}}
.modal-title{{font-size:1.15rem;font-weight:700;color:var(--text);margin-bottom:3px;line-height:1.4;}}
.modal-cvss{{font-size:.8rem;font-family:Consolas,monospace;}}
.modal-body{{overflow-y:auto;padding:6px 0 14px;flex:1;}}
.modal-section{{padding:12px 22px 0;}}
.modal-section-title{{display:flex;align-items:center;gap:7px;font-size:.84rem;font-weight:700;color:var(--text);margin-bottom:7px;}}
.modal-section-bar{{width:3px;height:1em;border-radius:2px;flex-shrink:0;}}
.modal-text{{font-size:.88rem;color:var(--text);line-height:1.75;white-space:pre-wrap;}}
.modal-code{{background:var(--bg);border-radius:8px;padding:9px 13px;font-family:Consolas,monospace;font-size:.8rem;color:#a5d6a7;word-break:break-all;white-space:pre-wrap;margin-top:3px;}}
.modal-ref{{font-size:.8rem;color:var(--dim);margin:3px 0;padding-left:14px;position:relative;}}
.modal-ref::before{{content:"•";position:absolute;left:0;font-weight:700;}}
.modal-footer{{background:var(--surface2);padding:11px 22px;display:flex;justify-content:flex-end;align-items:center;gap:10px;flex-shrink:0;}}
.modal-nav{{background:transparent;border:1px solid rgba(255,255,255,.15);color:var(--dim);padding:5px 13px;border-radius:6px;font-size:.8rem;cursor:pointer;transition:all .15s;}}
.modal-nav:hover{{background:var(--surface3);color:var(--text);}}
.modal-nav:disabled{{opacity:.3;cursor:default;}}
.modal-close{{background:var(--accent);color:#fff;border:none;padding:6px 18px;border-radius:8px;font-size:.86rem;font-weight:600;cursor:pointer;}}
.modal-close:hover{{background:#1565c0;}}
.footer{{text-align:center;color:var(--dim);font-size:.78rem;padding:18px 48px 24px;border-top:1px solid var(--surface2);}}
@media print{{body{{background:#fff;color:#111;}}.modal-backdrop{{display:none!important;}}}}
</style>
</head>
<body>
<header class="header">
  <div class="header-inner">
    <div class="brand">
      <span class="brand-icon">🛡</span>
      <div><div class="brand-name">FirmwareGuard</div><div class="brand-sub">Firmware Security Analysis Report</div></div>
    </div>
    <div style="font-size:.95rem;color:#9fa8da;margin-bottom:12px;">Target: <strong style="color:#e8eaf6">{filename}</strong></div>
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">File</div><div class="meta-value">{filename}</div></div>
      <div class="meta-item"><div class="meta-label">Size</div><div class="meta-value">{size}</div></div>
      <div class="meta-item"><div class="meta-label">Type</div><div class="meta-value">{ftype}</div></div>
      <div class="meta-item"><div class="meta-label">Entropy</div><div class="meta-value">{entropy}</div></div>
      <div class="meta-item"><div class="meta-label">Scan Time</div><div class="meta-value">{scan_time}</div></div>
      <div class="meta-item"><div class="meta-label">SHA-256</div><div class="meta-value" title="{sha256}">{sha256_short}…</div></div>
    </div>
  </div>
</header>
<main class="main">
  <div class="summary">
    <div class="sev-card" style="--c:#b71c1c"><div class="sev-count">{n_critical}</div><div class="sev-label">🔴 Critical</div></div>
    <div class="sev-card" style="--c:#c62828"><div class="sev-count">{n_high}</div><div class="sev-label">🟠 High</div></div>
    <div class="sev-card" style="--c:#e65100"><div class="sev-count">{n_medium}</div><div class="sev-label">🟡 Medium</div></div>
    <div class="sev-card" style="--c:#f57f17"><div class="sev-count">{n_low}</div><div class="sev-label">🔵 Low</div></div>
    <div class="sev-card" style="--c:#37474f"><div class="sev-count">{n_info}</div><div class="sev-label">ℹ️ Info</div></div>
    <div class="sev-card" style="--c:#2e7d32"><div class="sev-count">{n_ok}</div><div class="sev-label">✅ Passed</div></div>
    <div class="sev-card" style="--c:var(--accent)"><div class="sev-count">{n_total}</div><div class="sev-label">📋 Total</div></div>
  </div>
  <div class="gauge-row">
    <div class="gauge-wrap">
      <svg class="gauge-svg" width="100" height="100" viewBox="0 0 110 110">
        <circle class="gauge-bg" cx="55" cy="55" r="50"/>
        <circle class="gauge-arc" cx="55" cy="55" r="50"/>
      </svg>
      <div class="gauge-text"><span class="gauge-score">{risk_score}</span><span class="gauge-unit">/100</span></div>
    </div>
    <div class="risk-info">
      <h2>{risk_label}</h2>
      <p>{n_critical} critical &nbsp;·&nbsp; {n_high} high &nbsp;·&nbsp; {n_medium} medium &nbsp;·&nbsp; {n_low} low findings detected.<br>
      <span style="color:var(--accent);font-size:.84rem;">💡 Click any finding row to see full description, impact &amp; remediation.</span></p>
    </div>
  </div>
  <div class="section-title">Findings by Category</div>
  <div class="cat-grid">{cats_html}</div>
  <div class="section-title">All Findings</div>
  <input class="search-box" id="searchBox" placeholder="🔍  Filter findings by keyword…" oninput="filterTable()">
  <div class="filter-bar">
    <button class="filter-btn active" onclick="setFilter('ALL',this)">All</button>
    <button class="filter-btn" onclick="setFilter('CRITICAL',this)">🔴 Critical</button>
    <button class="filter-btn" onclick="setFilter('HIGH',this)">🟠 High</button>
    <button class="filter-btn" onclick="setFilter('MEDIUM',this)">🟡 Medium</button>
    <button class="filter-btn" onclick="setFilter('LOW',this)">🔵 Low</button>
    <button class="filter-btn" onclick="setFilter('INFO',this)">ℹ️ Info</button>
    <button class="filter-btn" onclick="setFilter('OK',this)">✅ OK</button>
  </div>
  <div class="findings-wrap">
    <table id="findingsTable">
      <thead><tr>
        <th style="width:105px">Severity</th>
        <th style="width:155px">Category</th>
        <th>Finding <span class="click-hint">— click for details</span></th>
        <th>Location / Evidence</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</main>
<footer class="footer">Generated by <strong>FirmwareGuard</strong> on {scan_time} &nbsp;·&nbsp; For security assessment purposes only.</footer>

<div class="modal-backdrop" id="modalBackdrop" onclick="backdropClick(event)">
  <div class="modal" id="modal">
    <div class="modal-bar" id="modalBar"></div>
    <div class="modal-header">
      <div><span class="modal-pill" id="modalPill"></span><span class="modal-cat" id="modalCat"></span></div>
      <div class="modal-title" id="modalTitle"></div>
      <div class="modal-cvss" id="modalCvss"></div>
    </div>
    <div class="modal-body" id="modalBody"></div>
    <div class="modal-footer">
      <button class="modal-nav" id="btnPrev" onclick="navModal(-1)">◀ Prev</button>
      <span id="modalCounter" style="font-size:.78rem;color:var(--dim)"></span>
      <button class="modal-nav" id="btnNext" onclick="navModal(1)">Next ▶</button>
      <button class="modal-close" onclick="document.getElementById('modalBackdrop').classList.remove('open')">Close</button>
    </div>
  </div>
</div>

<script>
const FINDINGS = {findings_json};
const SEV_COLORS = {{CRITICAL:"#b71c1c",HIGH:"#c62828",MEDIUM:"#e65100",LOW:"#f57f17",INFO:"#37474f",OK:"#1b5e20"}};
let curIdx=0, visIdx=FINDINGS.map((_,i)=>i), activeFilter='ALL', searchTerm='';

function openModal(i){{curIdx=i;renderModal();document.getElementById('modalBackdrop').classList.add('open');}}
function backdropClick(e){{if(e.target===document.getElementById('modalBackdrop'))document.getElementById('modalBackdrop').classList.remove('open');}}
function navModal(d){{const p=visIdx.indexOf(curIdx)+d;if(p>=0&&p<visIdx.length){{curIdx=visIdx[p];renderModal();}}}}

function renderModal(){{
  const f=FINDINGS[curIdx], color=SEV_COLORS[f.severity]||'#1e88e5', pos=visIdx.indexOf(curIdx);
  document.getElementById('modalBar').style.background=color;
  document.getElementById('modalPill').textContent=f.severity;
  document.getElementById('modalPill').style.background=color;
  document.getElementById('modalCat').textContent=f.category;
  document.getElementById('modalTitle').textContent=f.title;
  document.getElementById('modalCvss').textContent=f.cvss?'CVSS  '+f.cvss:'';
  document.getElementById('modalCvss').style.color=color;
  document.getElementById('modalCounter').textContent=(pos+1)+' / '+visIdx.length;
  document.getElementById('btnPrev').disabled=pos===0;
  document.getElementById('btnNext').disabled=pos===visIdx.length-1;
  const body=document.getElementById('modalBody');
  body.innerHTML='';
  if(f.detail)body.appendChild(sect('📍 Location / Evidence',codeEl(f.detail),color));
  if(f.description)body.appendChild(sect('📖 Description',paraEl(f.description),color));
  if(f.impact)body.appendChild(sect('💥 Impact',paraEl(f.impact),color));
  if(f.remediation)body.appendChild(sect('🔧 Remediation',paraEl(f.remediation),color));
  if(f.references&&f.references.length){{
    const rd=document.createElement('div');
    f.references.forEach(r=>{{const d=document.createElement('div');d.className='modal-ref';d.textContent=r;rd.appendChild(d);}});
    body.appendChild(sect('🔗 References',rd,color));
  }}
  body.scrollTop=0;
}}

function sect(title,content,color){{
  const w=document.createElement('div');w.className='modal-section';
  const h=document.createElement('div');h.className='modal-section-title';
  const b=document.createElement('div');b.className='modal-section-bar';b.style.background=color;
  h.appendChild(b);h.appendChild(document.createTextNode(' '+title));
  w.appendChild(h);w.appendChild(content);return w;
}}
function paraEl(t){{const p=document.createElement('div');p.className='modal-text';p.textContent=t;return p;}}
function codeEl(t){{const c=document.createElement('div');c.className='modal-code';c.textContent=t;return c;}}

document.addEventListener('keydown',e=>{{
  const open=document.getElementById('modalBackdrop').classList.contains('open');
  if(e.key==='Escape'&&open)document.getElementById('modalBackdrop').classList.remove('open');
  if(e.key==='ArrowRight'&&open)navModal(1);
  if(e.key==='ArrowLeft'&&open)navModal(-1);
}});

function setFilter(sev,btn){{
  activeFilter=sev;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');applyFilters();
}}
function filterTable(){{searchTerm=document.getElementById('searchBox').value.toLowerCase();applyFilters();}}
function applyFilters(){{
  visIdx=[];
  document.querySelectorAll('#findingsTable tbody tr').forEach(row=>{{
    const ok=(activeFilter==='ALL'||row.dataset.sev===activeFilter)&&(!searchTerm||row.textContent.toLowerCase().includes(searchTerm));
    row.style.display=ok?'':'none';
    if(ok)visIdx.push(parseInt(row.dataset.idx));
  }});
}}
</script>
</body>
</html>"""

    def _rows(self, findings):
        html = []
        for i, f in enumerate(findings):
            sev  = f.get("severity", "INFO")
            cat  = f.get("category", "")
            title= f.get("title", "")
            det  = f.get("detail", "")
            clr, bg, ico = SEV_COLOR.get(sev, ("#607d8b","#eceff1","ℹ️"))
            html.append(
                f'<tr data-sev="{sev}" data-idx="{i}" onclick="openModal({i})" title="Click for full details">'
                f'<td><span class="sev-pill" style="background:{bg};color:{clr}">{ico} {sev}</span></td>'
                f'<td>{self._esc(cat)}</td>'
                f'<td><strong>{self._esc(title)}</strong></td>'
                f'<td class="detail-text">{self._esc(det)}</td>'
                f'</tr>'
            )
        return "\n".join(html)

    def _category_cards(self, cats):
        html = []
        for cat, flist in sorted(cats.items()):
            cnt = Counter(f.get("severity","INFO") for f in flist)
            badges = ""
            for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","OK"]:
                n = cnt.get(sev, 0)
                if n:
                    clr, bg, ico = SEV_COLOR[sev]
                    badges += (f'<span class="cat-badge" style="background:{bg};color:{clr}">'
                               f'{ico} {n} {sev}</span>')
            html.append(f'<div class="cat-card"><h3>{self._esc(cat)}</h3>{badges}</div>')
        return "\n".join(html)

    @staticmethod
    def _esc(s):
        return (str(s).replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace('"',"&quot;"))
