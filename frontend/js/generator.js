/*
 * Secure password / example passphrase generator UI.
 * Randomness comes from the server's `secrets` module (a CSPRNG).
 * Generated values are shown once and never stored by this page.
 */
(function () {
  "use strict";
  const { postJSON } = window.PSA;

  const pwButton = document.getElementById("gen-password-button");
  const pwOutput = document.getElementById("gen-password-output");
  const pwMeta = document.getElementById("gen-password-meta");
  const copyButton = document.getElementById("gen-copy");
  const analyzeButton = document.getElementById("gen-analyze");

  const ppButton = document.getElementById("gen-passphrase-button");
  const ppOutput = document.getElementById("gen-passphrase-output");
  const ppMeta = document.getElementById("gen-passphrase-meta");

  pwButton.addEventListener("click", async function () {
    try {
      const data = await postJSON("/api/generate-password", {
        length: Number(document.getElementById("gen-length").value),
        uppercase: document.getElementById("gen-upper").checked,
        lowercase: document.getElementById("gen-lower").checked,
        digits: document.getElementById("gen-digits").checked,
        symbols: document.getElementById("gen-symbols").checked,
      });
      pwOutput.textContent = data.password;
      pwMeta.textContent = data.length + " characters, about " + data.entropy_bits +
        " bits if generated uniformly at random. " + data.note;
      copyButton.disabled = false;
      analyzeButton.disabled = false;
    } catch (error) {
      pwOutput.textContent = "";
      pwMeta.textContent = error.message;
      copyButton.disabled = true;
      analyzeButton.disabled = true;
    }
  });

  copyButton.addEventListener("click", async function () {
    try {
      await navigator.clipboard.writeText(pwOutput.textContent);
      copyButton.textContent = "Copied";
      setTimeout(function () { copyButton.textContent = "Copy"; }, 1500);
    } catch (error) {
      copyButton.textContent = "Copy failed - select and copy manually";
    }
  });

  analyzeButton.addEventListener("click", function () {
    if (window.PSA.analyzePassword) window.PSA.analyzePassword(pwOutput.textContent);
  });

  ppButton.addEventListener("click", async function () {
    try {
      const data = await postJSON("/api/generate-passphrase", {
        word_count: Number(document.getElementById("gen-words").value),
        separator: document.getElementById("gen-separator").value,
      });
      ppOutput.textContent = data.passphrase;
      ppMeta.textContent = data.word_count + " random words from the local list ≈ " + data.entropy_bits +
        " bits. " + data.note;
    } catch (error) {
      ppOutput.textContent = "";
      ppMeta.textContent = error.message;
    }
  });

  window.addEventListener("pagehide", function () {
    pwOutput.textContent = "";
    ppOutput.textContent = "";
  });
})();
