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

  /* row detail viewer */
  document.querySelectorAll("[data-row-json]").forEach((b) => {
    b.addEventListener("click", async () => {
      openModal('<div class="spinner"></div>', "Row details");
      try {
        const res = await fetch(b.dataset.rowJson);
        const j = await res.json();
        if (j.error) { openModal(esc(j.error), "Row details"); return; }
        let html = '<table class="tbl kv"><tbody>';
        for (const [k, v] of Object.entries(j.row)) {
          const disp = v.display === null ? '<span class="null">NULL</span>' : esc(v.display);
          html += `<tr><th class="mono">${esc(k)}</th><td class="mono prewrap">${disp}</td></tr>`;
        }
        html += "</tbody></table>";
        openModal(html, "Row details");
      } catch (e) {
        openModal(esc(String(e)), "Row details");
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

  /* SQL console */
  const qf = document.getElementById("queryForm");
  if (qf) {
    qf.addEventListener("submit", async (e) => {
      e.preventDefault();
      const sql = document.getElementById("sqlInput").value;
      const engine = document.getElementById("engineSelect")?.value || "auto";
      const out = document.getElementById("queryOut");
      out.innerHTML = '<div class="spinner"></div>';
      try {
        const res = await fetch("/api/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sql, engine }),
        });
        const j = await res.json();
        if (j.error) {
          out.innerHTML = `<div class="errbox">${esc(j.error)}</div>`;
          return;
        }
        let h = `<div class="okchip">${j.columns.length} column(s) - ${j.rows.length} row(s) - ${j.ms} ms</div>`;
        if (j.columns.length) {
          h += '<div class="table-wrap"><table class="tbl sortable mono"><thead><tr>';
          h += j.columns.map((c) => `<th data-key>${esc(c)}</th>`).join("");
          h += "</tr></thead><tbody>";
          h += j.rows
            .map(
              (r) =>
                "<tr>" +
                r.map((v) => `<td class="${v === null ? "null" : ""}">${v === null ? "NULL" : esc(String(v))}</td>`).join("") +
                "</tr>"
            )
            .join("");
          h += "</tbody></table></div>";
        }
        out.innerHTML = h;
      } catch (err) {
        out.innerHTML = `<div class="errbox">${esc(String(err))}</div>`;
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
