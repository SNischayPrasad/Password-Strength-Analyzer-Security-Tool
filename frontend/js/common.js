/*
 * Shared helpers.
 *
 * Privacy rules for ALL frontend code:
 *   - never console.log a password or API request body
 *   - never put a password in a URL, localStorage, sessionStorage or cookies
 *   - render server data with textContent (never innerHTML) to avoid XSS
 */
(function () {
  "use strict";

  async function postJSON(url, body, signal) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: signal,
      cache: "no-store",
      credentials: "same-origin",
    });
    const data = await response.json().catch(function () { return {}; });
    if (!response.ok) {
      const error = new Error(data.error || "Request failed (" + response.status + ").");
      error.status = response.status;
      throw error;
    }
    return data;
  }

  async function getJSON(url) {
    const response = await fetch(url, { cache: "no-store", credentials: "same-origin" });
    const data = await response.json().catch(function () { return {}; });
    if (!response.ok) throw new Error(data.error || "Request failed (" + response.status + ").");
    return data;
  }

  /* Create an element with optional class and text (text via textContent). */
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function debounce(fn, wait) {
    let timer = null;
    return function () {
      const args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(null, args); }, wait);
    };
  }

  window.PSA = { postJSON: postJSON, getJSON: getJSON, el: el, clear: clear, debounce: debounce };
})();
