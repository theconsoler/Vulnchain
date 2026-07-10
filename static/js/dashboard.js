// ── Theme Toggle ─────────────────────────────────────────────────────────────

(function() {
  // Apply saved theme immediately on load -- before paint to avoid flash
  const saved = localStorage.getItem("vulnchain_theme");
  if (saved === "light") {
    document.body.classList.add("light-theme");
    const icon = document.getElementById("themeIcon");
    if (icon) icon.textContent = "🌙";
  }
})();

function toggleTheme() {
  const body    = document.body;
  const icon    = document.getElementById("themeIcon");
  const isLight = body.classList.toggle("light-theme");

  icon.textContent = isLight ? "🌙" : "☀️";
  localStorage.setItem("vulnchain_theme", isLight ? "light" : "dark");
}


// ── Auto-refresh stats every 60s on overview page ────────────────────────────

if (document.getElementById("totalNodes")) {
  function loadStats() {
    fetch("/api/stats")
      .then(r => r.json())
      .then(d => {
        document.getElementById("totalNodes").textContent   = d.total_nodes        ?? "--";
        document.getElementById("exploitNodes").textContent = d.nodes_with_exploit ?? "--";
        document.getElementById("highEpss").textContent     = d.vulns_high_epss    ?? "--";
        document.getElementById("pathCount").textContent    = d.attack_path_count  ?? "--";
      })
      .catch(() => {});
  }
  loadStats();
  setInterval(loadStats, 60000);
}
