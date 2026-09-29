/*
 * Real-time password strength meter.
 *
 * As the user types, the password is sent (debounced) to POST /api/analyze in
 * a JSON body with record=false, so real-time checks never reach analytics.
 * Only the explicit "Add result to anonymous stats" button sends record=true,
 * and even then the server stores metadata only.
 */
(function () {
  "use strict";
  const { postJSON, el, clear, debounce } = window.PSA;

  const input = document.getElementById("password");
  const toggle = document.getElementById("toggle-visibility");
  const clearButton = document.getElementById("clear-password");
  const recordButton = document.getElementById("record-button");
  const recordStatus = document.getElementById("record-status");
  const ctxFields = {
    first_name: document.getElementById("ctx-first-name"),
    birth_year: document.getElementById("ctx-birth-year"),
    organization: document.getElementById("ctx-organization"),
  };

  const readout = document.getElementById("readout");
  const classificationEl = document.getElementById("classification");
  const scoreEl = document.getElementById("score");
  const meter = document.getElementById("meter");
  const meterFill = document.getElementById("meter-fill");
  const cells = document.getElementById("cells");
  const legend = document.getElementById("legend");
  const checks = document.getElementById("checks");
  const findingsList = document.getElementById("findings");
  const suggestionsList = document.getElementById("suggestions");
  const guessTable = document.getElementById("guess-table").querySelector("tbody");
  const guessDisclaimer = document.getElementById("guess-disclaimer");
  const breakdownTable = document.getElementById("breakdown-table").querySelector("tbody");
  const policyStatus = document.getElementById("policy-status");
  const policyRules = document.getElementById("policy-rules");

  const MAX_CELLS = 64;
  const PATTERN_LABELS = {
    sequence: "Sequence",
    keyboard_pattern: "Keyboard walk",
    repetition: "Repetition",
    dictionary_word: "Dictionary word",
    date: "Year / date",
    personal_info: "Personal info",
  };
  // Where two patterns overlap, the tile shows the more serious one.
  const PATTERN_PRIORITY = ["personal_info", "keyboard_pattern", "repetition", "sequence", "date", "dictionary_word"];

  let controller = null;
  let lastResult = null;

  function context() {
    const ctx = {};
    Object.keys(ctxFields).forEach(function (key) {
      const value = ctxFields[key].value.trim();
      if (value) ctx[key] = value;
    });
    return ctx;
  }

  /* ---------------- rendering ---------------- */

  function renderEmpty() {
    lastResult = null;
    readout.removeAttribute("data-class");
    classificationEl.textContent = "—";
    scoreEl.textContent = "0";
    meter.setAttribute("aria-valuenow", "0");
    meterFill.style.width = "0%";
    clear(cells);
    cells.appendChild(el("span", "cells-empty", "Each character appears here as a tile. Tiles are underlined by the pattern they belong to."));
    clear(legend);
    clear(checks);
    clear(findingsList);
    findingsList.appendChild(el("li", "empty-state", "No password analyzed yet."));
    clear(suggestionsList);
    suggestionsList.appendChild(el("li", "empty-state", "Suggestions appear once you start typing."));
    ["m-length", "m-types", "m-unique", "m-pool", "m-theoretical", "m-adjusted"].forEach(function (id) {
      clear(document.getElementById(id));
      document.getElementById(id).textContent = "—";
    });
    clear(guessTable);
    const row = el("tr");
    const cell = el("td", "empty-state", "—");
    cell.colSpan = 2;
    row.appendChild(cell);
    guessTable.appendChild(row);
    clear(breakdownTable);
    policyStatus.textContent = "—";
    policyStatus.className = "policy-status";
    clear(policyRules);
    recordButton.disabled = true;
  }

  function renderMeter(result) {
    readout.setAttribute("data-class", result.classification);
    classificationEl.textContent = result.classification;
    scoreEl.textContent = String(result.score);
    meter.setAttribute("aria-valuenow", String(result.score));
    meter.setAttribute("aria-valuetext", result.score + " out of 100, " + result.classification);
    meterFill.style.width = Math.max(result.score, 2) + "%";
  }

  function renderPatternMap(result) {
    // Characters are only drawn when "Show password" is on - and they come
    // from the local input field, never from the server response.
    const value = input.value;
    const show = input.type === "text";
    const chars = Array.from(value);
    const types = new Array(chars.length).fill(null);
    const segments = result.metrics.pattern_map || [];
    PATTERN_PRIORITY.slice().reverse().forEach(function (type) {
      segments.forEach(function (seg) {
        if (seg.type !== type) return;
        for (let i = seg.start; i < seg.end && i < types.length; i++) types[i] = type;
      });
    });

    clear(cells);
    const visible = Math.min(chars.length, MAX_CELLS);
    for (let i = 0; i < visible; i++) {
      const tile = el("span", "cell", show ? chars[i] : "•");
      if (types[i]) {
        tile.setAttribute("data-type", types[i]);
        tile.title = PATTERN_LABELS[types[i]];
      }
      tile.setAttribute("aria-hidden", "true");
      cells.appendChild(tile);
    }
    if (chars.length > MAX_CELLS) cells.appendChild(el("span", "cells-more", "+" + (chars.length - MAX_CELLS)));

    clear(legend);
    const present = PATTERN_PRIORITY.filter(function (t) { return types.indexOf(t) !== -1; });
    if (!present.length) {
      legend.appendChild(el("span", null, "No positional patterns detected."));
    }
    present.forEach(function (type) {
      const item = el("span");
      item.setAttribute("data-type", type);
      item.appendChild(el("i"));
      item.appendChild(document.createTextNode(PATTERN_LABELS[type]));
      legend.appendChild(item);
    });
  }

  function renderChecks(result) {
    clear(checks);
    result.checks.forEach(function (check) {
      checks.appendChild(el("li", check.passed ? "pass" : "fail", check.label));
    });
  }

  function renderFindings(result) {
    clear(findingsList);
    if (!result.findings.length) {
      findingsList.appendChild(el("li", "empty-state", "No known weak patterns detected. That is necessary, not sufficient: uniqueness and MFA still matter."));
      return;
    }
    result.findings.forEach(function (finding) {
      const item = el("li", "finding");
      item.setAttribute("data-severity", finding.severity);
      const title = el("div", "finding-title");
      title.appendChild(el("span", null, finding.title));
      title.appendChild(el("span", "severity", finding.severity));
      item.appendChild(title);
      item.appendChild(el("p", null, finding.description));
      findingsList.appendChild(item);
    });
  }

  function renderSuggestions(result) {
    clear(suggestionsList);
    result.suggestions.forEach(function (text) {
      suggestionsList.appendChild(el("li", null, text));
    });
  }

  function setMetric(id, main, sub) {
    const node = document.getElementById(id);
    clear(node);
    node.appendChild(document.createTextNode(main));
    if (sub) node.appendChild(el("small", null, sub));
  }

  function renderMetrics(result) {
    const m = result.metrics;
    setMetric("m-length", String(m.length), m.length_label);
    const typesNode = document.getElementById("m-types");
    clear(typesNode);
    typesNode.appendChild(document.createTextNode(m.character_type_count + " of 4"));
    const chips = el("span", "chips");
    [["lowercase", "a-z"], ["uppercase", "A-Z"], ["digits", "0-9"], ["symbols", "#$!"], ["spaces", "space"], ["non_ascii", "unicode"]]
      .forEach(function (pair) {
        chips.appendChild(el("span", "chip" + (m.character_types[pair[0]] ? " on" : ""), pair[1]));
      });
    typesNode.appendChild(chips);
    setMetric("m-unique", String(m.unique_character_count), "ratio " + m.unique_character_ratio.toFixed(2));
    setMetric("m-pool", String(m.pool_size), "estimated characters to choose from");
    setMetric("m-theoretical", m.theoretical_entropy_bits.toFixed(1) + " bits", "if every character were random");
    setMetric("m-adjusted", m.adjusted_entropy_bits.toFixed(1) + " bits", "after pricing detected patterns");

    guessDisclaimer.textContent = m.guess_resistance.disclaimer;
    clear(guessTable);
    m.guess_resistance.scenarios.forEach(function (s) {
      const row = el("tr");
      row.appendChild(el("td", null, s.label));
      row.appendChild(el("td", "num", s.time));
      guessTable.appendChild(row);
    });

    const b = m.score_breakdown;
    clear(breakdownTable);
    const addRow = function (label, value) {
      const row = el("tr");
      row.appendChild(el("td", null, label));
      row.appendChild(el("td", "num", value));
      breakdownTable.appendChild(row);
    };
    const labels = {
      length: "Length (max 35)", character_diversity: "Character diversity (max 15)",
      unique_character_ratio: "Unique-character ratio (max 10)", pattern_resistance: "Pattern resistance (max 20)",
      not_common_password: "Not a common password (max 10)", additional_unpredictability: "Additional unpredictability (max 10)",
    };
    Object.keys(b.contributions || {}).forEach(function (key) {
      addRow(labels[key] || key, "+" + b.contributions[key]);
    });
    (b.penalties || []).forEach(function (p) {
      addRow("Penalty: " + p.type.replace(/_/g, " ") + " (base " + p.base + ")", "−" + p.applied);
    });
    (b.caps || []).forEach(function (cap) { addRow("Cap: " + cap, ""); });
    addRow("Final score", String(result.score));
  }

  function renderPolicy(result) {
    const policy = result.policy;
    policyStatus.textContent = policy.status;
    policyStatus.className = "policy-status " + (policy.passed ? "pass" : "fail");
    clear(policyRules);
    policy.rules.forEach(function (rule) {
      policyRules.appendChild(el("li", rule.passed ? "pass" : "fail", rule.message));
    });
  }

  function render(result) {
    lastResult = result;
    renderMeter(result);
    renderPatternMap(result);
    renderChecks(result);
    renderFindings(result);
    renderSuggestions(result);
    renderMetrics(result);
    renderPolicy(result);
    recordButton.disabled = false;
  }

  /* ---------------- analysis ---------------- */

  async function analyze(record) {
    const password = input.value;
    if (!password) {
      if (controller) controller.abort();
      renderEmpty();
      return null;
    }
    if (controller) controller.abort();
    controller = new AbortController();
    try {
      const result = await postJSON("/api/analyze",
        { password: password, context: context(), record: Boolean(record) }, controller.signal);
      // Ignore stale responses if the field changed meanwhile.
      if (input.value === password) render(result);
      return result;
    } catch (error) {
      if (error.name === "AbortError") return null;
      recordStatus.textContent = error.message; // generic server message, never the password
      return null;
    }
  }

  const analyzeSoon = debounce(function () { analyze(false); }, 180);

  input.addEventListener("input", function () {
    recordStatus.textContent = "Saves score, class and length only — never the password.";
    analyzeSoon();
  });
  Object.keys(ctxFields).forEach(function (key) {
    ctxFields[key].addEventListener("input", analyzeSoon);
  });

  toggle.addEventListener("click", function () {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(show));
    toggle.textContent = show ? "🙈 Hide password" : "👁 Show password";
    if (lastResult) renderPatternMap(lastResult);
    input.focus();
  });

  clearButton.addEventListener("click", function () {
    input.value = "";
    renderEmpty();
    input.focus();
  });

  recordButton.addEventListener("click", async function () {
    recordButton.disabled = true;
    const result = await analyze(true);
    if (result && result.recorded) {
      recordStatus.textContent = "Added to the dashboard: score " + result.score + ", " + result.classification + ". The password was not saved.";
    }
    recordButton.disabled = !input.value;
  });

  // Don't leave passwords sitting in the page when navigating away
  // (browsers may otherwise restore form values from the back/forward cache).
  window.addEventListener("pagehide", function () {
    input.value = "";
    Object.keys(ctxFields).forEach(function (key) { ctxFields[key].value = ""; });
  });

  // Allows the generator to hand a password to the analyzer.
  window.PSA.analyzePassword = function (value) {
    input.value = value;
    analyze(false);
    document.getElementById("analyzer").scrollIntoView({ behavior: "smooth", block: "start" });
  };

  renderEmpty();
})();
