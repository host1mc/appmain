/* DB Admin front-end: sortable tables, filter, modal, toasts, query console, animations */

function esc(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function toast(msg, cat) {
  const wrap = document.getElementById("toasts");
  if (!wrap) return;
  const el = document.createElement("div");
  el.className = "toast " + (cat === "message" || cat === "success" ? "success" : cat || "info");
  el.innerHTML = esc(msg);
  wrap.appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 300);
  }, 4200);
}

function openModal(html, title) {
  document.getElementById("modalTitle").textContent = title || "Details";
  document.getElementById("modalBody").innerHTML = html;
  document.getElementById("modalOverlay").classList.add("show");
}

function closeModal() {
  document.getElementById("modalOverlay").classList.remove("show");
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".hidden-alert").forEach((a) => {
    const cat = a.dataset.cat || "info";
    if (cat === "message") toast(a.textContent.trim(), "success");
    else toast(a.textContent.trim(), cat);
    a.remove();
  });

  const overlay = document.getElementById("modalOverlay");
  document.getElementById("modalClose").addEventListener("click", closeModal);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  /* sortable tables: click th with data-key */
  document.querySelectorAll(".tbl.sortable").forEach((tbl) => {
    const ths = Array.from(tbl.querySelectorAll("thead th[data-key]"));
    ths.forEach((th) => {
      th.addEventListener("click", () => {
        const i = ths.indexOf(th);
        const tbody = tbl.querySelector("tbody");
        if (!tbody) return;
        const asc = th.dataset.dir !== "asc";
        ths.forEach((t) => delete t.dataset.dir);
        th.dataset.dir = asc ? "asc" : "desc";
        const rows = Array.from(tbody.querySelectorAll("tr"));
        rows.sort((a, b) => {
          const ac = a.cells[i], bc = b.cells[i];
          let x = (ac && (ac.dataset.v !== undefined ? ac.dataset.v : ac.textContent.trim())) || "";
          let y = (bc && (bc.dataset.v !== undefined ? bc.dataset.v : bc.textContent.trim())) || "";
          const nx = parseFloat(String(x).replace(/[^0-9.\-]/g, ""));
          const ny = parseFloat(String(y).replace(/[^0-9.\-]/g, ""));
          if (!isNaN(nx) && !isNaN(ny)) { x = nx; y = ny; }
          const r = x < y ? -1 : x > y ? 1 : 0;
          return asc ? r : -r;
        });
        rows.forEach((r) => tbody.appendChild(r));
      });
    });
  });

  /* row detail viewer — clicking a table row opens a modal with all columns */
  document.querySelectorAll("tbody[data-row-json]").forEach((tbody) => {
    const baseUrl = tbody.dataset.rowJson;
    tbody.addEventListener("click", (e) => {
      const row = e.target.closest("tr");
      if (!row || !row.dataset.rowId) return;
      const jsonUrl = baseUrl.replace("__RID__", encodeURIComponent(row.dataset.rowId));
      openModal('<div class="spinner"></div>', "Row details");
      fetch(jsonUrl)
        .then(res => res.json())
        .then(j => {
          if (j.error) { openModal('<div class="errbox">' + esc(j.error) + '</div>', "Row details"); return; }
          let html = '<table class="tbl kv"><tbody>';
          for (const [k, v] of Object.entries(j.row)) {
            const disp = v.display === null ? '<span class="null">NULL</span>' : esc(String(v.display));
            html += `<tr><th class="mono">${esc(k)}</th><td class="mono prewrap">${disp}</td></tr>`;
          }
          openModal(html + "</tbody></table>", "Row details");
        })
        .catch(err => openModal('<div class="errbox">' + esc(String(err)) + '</div>', "Row details"));
    });
  });

  /* inline table peek: [data-peek] reveals rows in a panel below the section,
     no navigation. Re-clicking the same target collapses it. */
  function peekTable(j) {
    let h = '<div class="table-wrap"><table class="tbl sortable mono"><thead><tr>';
    h += j.columns.map((c) => `<th data-key>${esc(c)}</th>`).join("");
    h += "</tr></thead><tbody>";
    h += j.rows.map((r) =>
      "<tr>" + r.map((v) => {
        const raw = v === null ? "" : String(v);
        return `<td class="${v === null ? "null" : ""}" data-v="${esc(raw)}">${cellHtml(v)}</td>`;
      }).join("") + "</tr>"
    ).join("");
    return h + "</tbody></table></div>";
  }

  document.querySelectorAll("[data-peek]").forEach((el) => {
    if (el.tagName !== "A" && el.hasAttribute("tabindex")) {
      el.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); el.click(); }
      });
    }
    el.addEventListener("click", async (e) => {
      e.preventDefault();
      const url = el.dataset.peek;
      const name = el.dataset.peekName || "rows";
      const host = el.closest(".grid-2") || el.closest(".panel") || el.parentElement;
      let peek = host.nextElementSibling;
      if (!peek || !peek.classList || !peek.classList.contains("peek-panel")) peek = null;
      if (peek && peek.dataset.for === url) { peek.remove(); return; }
      if (!peek) {
        peek = document.createElement("div");
        peek.className = "panel peek-panel";
        host.parentNode.insertBefore(peek, host.nextSibling);
      }
      peek.dataset.for = url;
      peek.innerHTML =
        `<div class="p-head"><span>▼ ${esc(name)}</span>` +
        `<button class="x" type="button" title="Close">&times;</button></div>` +
        `<div class="p-body"><div class="spinner"></div></div>`;
      peek.querySelector(".x").addEventListener("click", () => peek.remove());
      try {
        const res = await fetch(url);
        const j = await res.json();
        const body = peek.querySelector(".p-body");
        if (j.error) { body.innerHTML = `<div class="errbox">${esc(j.error)}</div>`; return; }
        peek.querySelector(".p-head span").textContent =
          `▼ ${name} · ${j.total} row(s)` + (j.shown < j.total ? ` (showing first ${j.shown})` : "");
        const full = j.href ? `<div style="padding:10px 12px 2px"><a class="btn sm" href="${j.href}">Open full view &rarr;</a></div>` : "";
        body.className = "p-body flush";
        body.innerHTML = j.columns.length ? peekTable(j) + full : `<div class="p-body"><div class="okchip">Empty table</div></div>`;
        bindSortable(peek);
        peek.querySelectorAll(".cell-expand").forEach((c) => c.addEventListener("click", () => c.classList.toggle("open")));
        peek.scrollIntoView({ behavior: "smooth", block: "nearest" });
      } catch (err) {
        peek.querySelector(".p-body").innerHTML = `<div class="errbox">${esc(String(err))}</div>`;
      }
    });
  });

  /* copy buttons */
  document.querySelectorAll("[data-copy]").forEach((b) => {
    b.addEventListener("click", () => {
      if (navigator.clipboard) navigator.clipboard.writeText(b.dataset.copy);
      toast("Copied to clipboard");
    });
  });

  /* destructive single actions: POST to data-post, with optional data-rowid /
     data-uid / data-next fields, confirming first when data-confirm is set */
  document.querySelectorAll("[data-post]").forEach((b) => {
    b.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (b.dataset.confirm && !confirm(b.dataset.confirm)) return;
      const form = document.createElement("form");
      form.method = "POST";
      form.action = b.dataset.post;
      const fields = { next: b.dataset.next, rowid: b.dataset.rowid, uid: b.dataset.uid };
      for (const [k, v] of Object.entries(fields)) {
        if (v === undefined || v === null || v === "") continue;
        const inp = document.createElement("input");
        inp.type = "hidden";
        inp.name = k;
        inp.value = v;
        form.appendChild(inp);
      }
      document.body.appendChild(form);
      form.submit();
    });
  });

  /* mass-select forms: form[data-mass] with named row checkboxes, an optional
     [data-check-all] toggle, a [data-mass-btn] submit and [data-mass-count] */
  document.querySelectorAll("form[data-mass]").forEach((form) => {
    const boxes = Array.from(form.querySelectorAll("input[type='checkbox'][name]"));
    const all = form.querySelector("[data-check-all]");
    const btn = form.querySelector("[data-mass-btn]");
    const cnt = form.querySelector("[data-mass-count]");
    function checked() {
      return boxes.filter((b) => b.checked).length;
    }
    function refresh() {
      const n = checked();
      if (cnt) cnt.textContent = n;
      if (btn) {
        btn.disabled = n === 0;
        btn.style.opacity = n === 0 ? ".45" : "1";
      }
      if (all) all.checked = n > 0 && n === boxes.length;
    }
    boxes.forEach((b) => b.addEventListener("change", refresh));
    if (all) {
      all.addEventListener("change", () => {
        boxes.forEach((b) => (b.checked = all.checked));
        refresh();
      });
    }
    form.addEventListener("submit", (e) => {
      if (!checked()) {
        e.preventDefault();
        return;
      }
      const msg = form.dataset.confirm || "Delete the selected item(s)? This cannot be undone.";
      if (!confirm(msg)) e.preventDefault();
    });
    refresh();
  });

  /* entrance animations (counters, bars, stacks, donuts) */
  const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);

  if (!reduced) {
    document.querySelectorAll("[data-anim='num']").forEach((el) => {
      const target = parseFloat(el.dataset.n || "0");
      const finalTxt = el.textContent;
      const dur = 900;
      const t0 = performance.now();
      (function tick(now) {
        const p = Math.min(1, (now - t0) / dur);
        el.textContent = Math.round(target * easeOut(p)).toLocaleString("en-US");
        if (p < 1) requestAnimationFrame(tick);
        else el.textContent = finalTxt;
      })(t0);
    });
  }

  requestAnimationFrame(() => {
    document.querySelectorAll("[data-anim='bar']").forEach((el) => {
      const w = Math.max(0, Math.min(100, parseFloat(el.dataset.w || "0"))) / 100;
      el.style.transform = "scaleX(" + w + ")";
    });
    document.querySelectorAll("[data-anim='stack']").forEach((el) => {
      el.querySelectorAll("[data-w]").forEach((c) => {
        const w = Math.max(0, Math.min(100, parseFloat(c.dataset.w || "0"))) / 100;
        c.style.transform = "scaleX(" + w + ")";
      });
    });
    document.querySelectorAll("[data-anim='donut']").forEach((el) => {
      const dash = parseFloat(el.dataset.dash || "0");
      const circ = parseFloat(el.dataset.circ || "339.292");
      el.style.strokeDasharray = dash + " " + circ;
    });
  });

  function bindSortable(root) {
    (root || document).querySelectorAll(".tbl.sortable").forEach((tbl) => {
      if (tbl.dataset.sortBound) return;
      tbl.dataset.sortBound = "1";
      const ths = Array.from(tbl.querySelectorAll("thead th[data-key]"));
      ths.forEach((th) => {
        th.addEventListener("click", () => {
          const i = ths.indexOf(th);
          const tbody = tbl.querySelector("tbody");
          if (!tbody) return;
          const asc = th.dataset.dir !== "asc";
          ths.forEach((t) => delete t.dataset.dir);
          th.dataset.dir = asc ? "asc" : "desc";
          const rows = Array.from(tbody.querySelectorAll("tr"));
          rows.sort((a, b) => {
            const ac = a.cells[i], bc = b.cells[i];
            let x = (ac && (ac.dataset.v !== undefined ? ac.dataset.v : ac.textContent.trim())) || "";
            let y = (bc && (bc.dataset.v !== undefined ? bc.dataset.v : bc.textContent.trim())) || "";
            const nx = parseFloat(String(x).replace(/[^0-9.\\-]/g, ""));
            const ny = parseFloat(String(y).replace(/[^0-9.\\-]/g, ""));
            if (!isNaN(nx) && !isNaN(ny) && String(x).match(/[0-9]/) && String(y).match(/[0-9]/)) {
              x = nx; y = ny;
            }
            const r = x < y ? -1 : x > y ? 1 : 0;
            return asc ? r : -r;
          });
          rows.forEach((r) => tbody.appendChild(r));
        });
      });
    });
  }

  function cellHtml(v) {
    if (v === null || v === undefined) return '<span class="null">NULL</span>';
    const s = String(v);
    const short = s.length > 80;
    const inner = esc(s);
    if (short) {
      return `<span class="cell-expand" title="${esc(s)}">${inner}</span>`;
    }
    return inner;
  }

  function rowsAsObjects(columns, rows) {
    return rows.map((r) => {
      const o = {};
      columns.forEach((c, i) => { o[c] = r[i]; });
      return o;
    });
  }

  function csvEscape(v) {
    if (v === null || v === undefined) return "";
    const s = String(v);
    if (/[",\n]/.test(s)) return '"' + s.replaceAll('"', '""') + '"';
    return s;
  }

  let lastQuery = null;
  let queryView = "table";

  function paintQuery(j) {
    const out = document.getElementById("queryOut");
    const meta = document.getElementById("queryMeta");
    lastQuery = j;
    if (meta) meta.textContent = `${j.columns.length} col · ${j.rows.length} row · ${j.ms} ms`;
    if (!j.columns.length) {
      out.innerHTML = `<div class="p-body"><div class="okchip">Statement finished in ${j.ms} ms — no result set</div></div>`;
      return;
    }
    const objs = rowsAsObjects(j.columns, j.rows);
    let body = "";
    if (queryView === "json") {
      body = `<pre class="result-json">${esc(JSON.stringify(objs, null, 2))}</pre>`;
    } else if (queryView === "cards") {
      body = '<div class="result-cards">' + objs.map((o, idx) => {
        let rows = Object.entries(o).map(([k, v]) =>
          `<div class="rc-row"><div class="rc-k">${esc(k)}</div><div class="rc-v">${v === null ? '<span class="null">NULL</span>' : esc(String(v))}</div></div>`
        ).join("");
        return `<div class="result-card"><div class="rc-i">#${idx + 1}</div>${rows}</div>`;
      }).join("") + "</div>";
    } else {
      body = '<div class="table-wrap"><table class="tbl sortable mono"><thead><tr>';
      body += j.columns.map((c) => `<th data-key>${esc(c)}</th>`).join("");
      body += "</tr></thead><tbody>";
      body += j.rows.map((r) =>
        "<tr>" + r.map((v) => {
          const raw = v === null ? "" : String(v);
          return `<td class="${v === null ? "null" : ""}" data-v="${esc(raw)}">${cellHtml(v)}</td>`;
        }).join("") + "</tr>"
      ).join("");
      body += "</tbody></table></div>";
    }
    out.innerHTML =
      `<div class="result-toolbar">
        <div class="okchip" style="margin:0">${j.columns.length} column(s) · ${j.rows.length} row(s) · ${j.ms} ms</div>
        <div class="seg" role="tablist">
          <button type="button" data-qview="table" class="${queryView === "table" ? "on" : ""}">Table</button>
          <button type="button" data-qview="cards" class="${queryView === "cards" ? "on" : ""}">Cards</button>
          <button type="button" data-qview="json" class="${queryView === "json" ? "on" : ""}">JSON</button>
        </div>
        <button type="button" class="btn sm ghost" id="copyCsv">Copy CSV</button>
        <button type="button" class="btn sm ghost" id="copyJson">Copy JSON</button>
      </div>` + body;
    bindSortable(out);
    out.querySelectorAll("[data-qview]").forEach((b) => {
      b.addEventListener("click", () => {
        queryView = b.dataset.qview;
        paintQuery(lastQuery);
      });
    });
    out.querySelectorAll(".cell-expand").forEach((el) => {
      el.addEventListener("click", () => el.classList.toggle("open"));
    });
    const csvBtn = document.getElementById("copyCsv");
    if (csvBtn) csvBtn.addEventListener("click", () => {
      const lines = [j.columns.map(csvEscape).join(",")];
      j.rows.forEach((r) => lines.push(r.map(csvEscape).join(",")));
      if (navigator.clipboard) navigator.clipboard.writeText(lines.join("\n"));
      toast("CSV copied");
    });
    const jsonBtn = document.getElementById("copyJson");
    if (jsonBtn) jsonBtn.addEventListener("click", () => {
      if (navigator.clipboard) navigator.clipboard.writeText(JSON.stringify(objs, null, 2));
      toast("JSON copied");
    });
  }

  /* SQL console */
  const qf = document.getElementById("queryForm");
  if (qf) {
    qf.addEventListener("submit", async (e) => {
      e.preventDefault();
      const sql = document.getElementById("sqlInput").value;
      const engine = document.getElementById("engineSelect")?.value || "auto";
      const out = document.getElementById("queryOut");
      const meta = document.getElementById("queryMeta");
      out.innerHTML = '<div class="spinner"></div>';
      if (meta) meta.textContent = "running…";
      try {
        const res = await fetch("/api/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sql, engine }),
        });
        const j = await res.json();
        if (j.error) {
          if (meta) meta.textContent = "error";
          out.innerHTML = `<div class="p-body"><div class="errbox">${esc(j.error)}</div></div>`;
          return;
        }
        paintQuery(j);
      } catch (err) {
        if (meta) meta.textContent = "error";
        out.innerHTML = `<div class="p-body"><div class="errbox">${esc(String(err))}</div></div>`;
      }
    });
    document.getElementById("sqlInput").addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        document.getElementById("queryForm").requestSubmit();
      }
    });
    const autoSize = () => {
      const ta = document.getElementById("sqlInput");
      ta.style.height = "auto";
      ta.style.height = Math.min(ta.scrollHeight, 520) + "px";
    };
    document.getElementById("sqlInput").addEventListener("input", autoSize);
    autoSize();
  }
});
