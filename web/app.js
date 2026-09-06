(() => {
  const rows = document.getElementById("rows");
  const empty = document.getElementById("empty");
  const live = document.getElementById("live");
  const mode = document.getElementById("mode");
  const ver = document.getElementById("ver");
  const filterEl = document.getElementById("filter");
  const pauseBtn = document.getElementById("pauseBtn");
  const clearBtn = document.getElementById("clearBtn");

  const state = {
    events: [],
    paused: false,
    filter: "",
    chip: "all",
    maxRows: 400,
  };

  const esc = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  function matches(ev) {
    const q = state.filter.trim().toLowerCase();
    if (state.chip === "tunnel" && !(ev.tags || "").includes("tunnel")) return false;
    if (state.chip === "telemetry" && !(ev.tags || "").includes("telemetry")) return false;
    if (state.chip === "block" && ev.action !== "block") return false;
    if (["crit", "high", "med"].includes(state.chip) && ev.severity !== state.chip) return false;
    if (!q) return true;
    const hay = [ev.qname, ev.process, ev.reason, ev.tags, ev.action, ev.severity]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  }

  function render() {
    const list = state.events.filter(matches).slice(-state.maxRows).reverse();
    empty.classList.toggle("show", list.length === 0);
    rows.innerHTML = list
      .map(
        (ev) => `
      <tr>
        <td class="time">${esc((ev.ts || "").slice(11, 19))}</td>
        <td><span class="sev ${esc(ev.severity)}">${esc(ev.severity)}</span></td>
        <td class="act ${esc(ev.action)}">${esc(ev.action)}</td>
        <td>${esc(ev.qtype)}</td>
        <td class="proc">${esc(ev.process || "—")}${ev.pid ? ` <span style="color:var(--muted)">#${esc(ev.pid)}</span>` : ""}</td>
        <td class="qname">${esc(ev.qname)}</td>
        <td class="reason">${esc(ev.reason)}${ev.tags ? ` <span style="color:var(--muted)">[${esc(ev.tags)}]</span>` : ""}</td>
        <td><button class="mini" data-block="${esc(ev.qname)}" type="button">block</button></td>
      </tr>`
      )
      .join("");
  }

  async function refreshStats() {
    try {
      const r = await fetch("/api/stats");
      const j = await r.json();
      for (const [k, v] of Object.entries(j)) {
        const el = document.querySelector(`[data-k="${k}"]`);
        if (el) el.textContent = v;
      }
      if (j.version) ver.textContent = "v" + j.version;
      mode.textContent = j.block_mode ? "enforce" : "alert-only";
    } catch (_) {}
  }

  function pushEvent(ev) {
    if (state.paused) return;
    state.events.push(ev);
    if (state.events.length > 2000) state.events.splice(0, state.events.length - 2000);
    render();
  }

  function connectSSE() {
    const es = new EventSource("/api/stream");
    es.onopen = () => {
      live.classList.remove("off");
      live.textContent = "LIVE";
    };
    es.onerror = () => {
      live.classList.add("off");
      live.textContent = "RECONNECT";
    };
    es.onmessage = (msg) => {
      try {
        pushEvent(JSON.parse(msg.data));
        refreshStats();
      } catch (_) {}
    };
  }

  filterEl.addEventListener("input", () => {
    state.filter = filterEl.value;
    render();
  });

  document.getElementById("sevChips").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-sev]");
    if (!btn) return;
    state.chip = btn.dataset.sev;
    document.querySelectorAll("#sevChips .chip").forEach((c) => c.classList.remove("on"));
    btn.classList.add("on");
    render();
  });

  pauseBtn.addEventListener("click", () => {
    state.paused = !state.paused;
    pauseBtn.textContent = state.paused ? "Resume" : "Pause";
    live.classList.toggle("off", state.paused);
    live.textContent = state.paused ? "PAUSED" : "LIVE";
  });

  clearBtn.addEventListener("click", () => {
    state.events = [];
    render();
  });

  rows.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-block]");
    if (!btn) return;
    const domain = btn.getAttribute("data-block");
    await fetch("/api/block", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    btn.textContent = "ok";
  });

  refreshStats();
  setInterval(refreshStats, 3000);
  connectSSE();
  render();
})();
