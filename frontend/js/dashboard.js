/*
 * Privacy-safe analytics dashboard.
 * Reads aggregate counts from GET /api/dashboard/stats. No passwords exist
 * in the data this page receives.
 */
(function () {
  "use strict";
  const { getJSON, el, clear } = window.PSA;

  const CLASSES = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"];
  const CLASS_VARS = {
    "VERY WEAK": "--s-very-weak", "WEAK": "--s-weak", "MODERATE": "--s-moderate",
    "STRONG": "--s-strong", "VERY STRONG": "--s-very-strong",
  };
  const WEAKNESS_LABELS = {
    common_password: "Common password", sequence: "Sequence", keyboard_pattern: "Keyboard walk",
    repetition: "Repetition", dictionary_word: "Dictionary word", predictable_structure: "Word + number structure",
    date: "Year / date", personal_info: "Personal info",
  };
  const charts = {};

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function fillTable(id, header, rows) {
    const table = document.getElementById(id);
    clear(table);
    const thead = el("thead");
    const hr = el("tr");
    hr.appendChild(el("th", null, header[0]));
    const th = el("th", "num", header[1]);
    hr.appendChild(th);
    thead.appendChild(hr);
    table.appendChild(thead);
    const tbody = el("tbody");
    rows.forEach(function (r) {
      const tr = el("tr");
      tr.appendChild(el("td", null, r[0]));
      tr.appendChild(el("td", "num", String(r[1])));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  function barChart(id, labels, values, colors, opts) {
    if (typeof window.Chart === "undefined") return; // CDN unavailable: tables still work
    opts = opts || {};
    const ink2 = cssVar("--ink-2");
    const rule = cssVar("--rule");
    if (charts[id]) charts[id].destroy();
    charts[id] = new window.Chart(document.getElementById(id), {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderRadius: 4,
          borderSkipped: "start",
          barPercentage: 0.7,
          categoryPercentage: 0.9,
          maxBarThickness: 44,
        }],
      },
      options: {
        indexAxis: opts.horizontal ? "y" : "x",
        maintainAspectRatio: false,
        animation: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? false : { duration: 300 },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                const v = opts.horizontal ? ctx.parsed.x : ctx.parsed.y;
                return (opts.valueLabel || "Analyses") + ": " + v + (opts.suffix || "");
              },
            },
          },
        },
        scales: {
          x: {
            grid: { display: Boolean(opts.horizontal), color: rule, drawTicks: false },
            border: { color: rule },
            ticks: { color: ink2, precision: 0 },
            beginAtZero: true,
            max: opts.max,
          },
          y: {
            grid: { display: !opts.horizontal, color: rule, drawTicks: false },
            border: { display: false },
            ticks: { color: ink2, precision: 0 },
            beginAtZero: true,
          },
        },
      },
    });
  }

  function render(stats) {
    document.getElementById("t-total").textContent = String(stats.total_analyses);
    document.getElementById("t-average").textContent = stats.total_analyses ? String(stats.average_score) : "—";
    CLASSES.forEach(function (c) {
      document.querySelector('[data-count="' + c + '"]').textContent = String(stats.classification_counts[c] || 0);
    });
    document.querySelectorAll(".tile i[data-class]").forEach(function (node) {
      node.style.background = cssVar(CLASS_VARS[node.getAttribute("data-class")]);
    });
    document.getElementById("empty-note").hidden = stats.total_analyses > 0;

    const accent = cssVar("--accent");

    // 1. Strength distribution (ordinal classes, coloured like the meter)
    const classValues = CLASSES.map(function (c) { return stats.classification_counts[c] || 0; });
    barChart("chart-strength", CLASSES.map(function (c) { return c.toLowerCase(); }), classValues,
      CLASSES.map(function (c) { return cssVar(CLASS_VARS[c]); }));
    fillTable("table-strength", ["Classification", "Analyses"],
      CLASSES.map(function (c, i) { return [c, classValues[i]]; }));

    // 2. Score distribution (single series, one colour)
    const scoreLabels = Object.keys(stats.score_distribution);
    const scoreValues = scoreLabels.map(function (k) { return stats.score_distribution[k]; });
    barChart("chart-score", scoreLabels, scoreValues, accent);
    fillTable("table-score", ["Score range", "Analyses"], scoreLabels.map(function (k, i) { return [k, scoreValues[i]]; }));

    // 3. Weakness types (% of analyses showing each)
    const weak = stats.weakness_types || [];
    const weakLabels = weak.map(function (w) { return WEAKNESS_LABELS[w.type] || w.type; });
    const weakValues = weak.map(function (w) { return w.percent_of_analyses; });
    barChart("chart-weakness", weakLabels, weakValues, accent,
      { horizontal: true, suffix: "%", valueLabel: "Share of analyses", max: 100 });
    fillTable("table-weakness", ["Weakness type", "% of analyses"],
      weak.map(function (w, i) { return [weakLabels[i], w.percent_of_analyses + "% (" + w.count + ")"]; }));

    // 4. Length distribution
    const lenLabels = Object.keys(stats.length_distribution);
    const lenValues = lenLabels.map(function (k) { return stats.length_distribution[k]; });
    barChart("chart-length", lenLabels.map(function (l) { return l + " chars"; }), lenValues, accent);
    fillTable("table-length", ["Length", "Analyses"], lenLabels.map(function (k, i) { return [k, lenValues[i]]; }));

    // 5. Weaknesses detected per analysis
    const patLabels = Object.keys(stats.weaknesses_per_analysis);
    const patValues = patLabels.map(function (k) { return stats.weaknesses_per_analysis[k]; });
    barChart("chart-patterns", patLabels.map(function (l) { return l + (l === "1" ? " weakness" : " weaknesses"); }), patValues, accent);
    fillTable("table-patterns", ["Weaknesses found", "Analyses"], patLabels.map(function (k, i) { return [k, patValues[i]]; }));

    document.getElementById("updated").textContent = "Updated " + new Date().toLocaleTimeString();
  }

  async function load() {
    try {
      render(await getJSON("/api/dashboard/stats"));
    } catch (error) {
      document.getElementById("updated").textContent = error.message;
    }
  }

  document.getElementById("refresh").addEventListener("click", load);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", load);
  load();
})();
