const patterns = {
  url: /https?:\/\/[^\s"'<>]+/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,
  windows_user: /\b[A-Za-z0-9_-]+\\[A-Za-z0-9._$-]+\b/gi,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/gi,
  mac: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/gi,
  ipv6: /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/gi,
  domain: /\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|uk|local|internal|corp|cloud|dev|app|be|tr|eu)\b/gi,
  hostname: /\b(?:DESKTOP|LAPTOP|SRV|SERVER|DC|WIN|PC|HOST)-[A-Za-z0-9-]+\b/gi,
  guid: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/gi,
  hash: /\b[a-fA-F0-9]{32,64}\b/gi,
};

const fakeValue = {
  url: (index) => `https://example${index}.com/path`,
  email: (index) => `john.smith${index}@example.com`,
  windows_user: (index) => `DOMAIN\\john.smith${index}`,
  ipv4: (index) => `10.10.${Math.floor(index / 254)}.${(index % 254) + 1}`,
  ipv6: (index) => `fd00::${index}`,
  domain: (index) => `example${index}.com`,
  hostname: (index) => `HOST-${String(index).padStart(4, "0")}`,
  mac: (index) => `00:11:22:33:44:${(index % 255).toString(16).padStart(2, "0")}`,
  guid: (index) => `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`,
  hash: (index) => index.toString(16).padStart(64, "0"),
};

const sourceText = document.querySelector("#source-text");
const outputText = document.querySelector("#output-text");
const fileInput = document.querySelector("#file-input");
const findingsContainer = document.querySelector("#findings");
const statusBox = document.querySelector("#status");

let currentFindings = {};

function detect(text) {
  const findings = {};

  for (const [category, pattern] of Object.entries(patterns)) {
    pattern.lastIndex = 0;
    const values = new Set();
    for (const match of text.matchAll(pattern)) {
      values.add(match[0]);
    }
    if (values.size > 0) {
      findings[category] = [...values].sort((a, b) => a.localeCompare(b));
    }
  }

  return findings;
}

function renderFindings(findings) {
  findingsContainer.innerHTML = "";
  const entries = Object.entries(findings);

  if (entries.length === 0) {
    findingsContainer.className = "findings empty";
    findingsContainer.textContent = "No sensitive-looking values detected.";
    return;
  }

  findingsContainer.className = "findings";
  for (const [category, values] of entries) {
    const item = document.createElement("div");
    item.className = "finding";

    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = category;
    checkbox.checked = true;
    checkbox.dataset.category = category;

    const name = document.createElement("span");
    name.textContent = category.replace("_", " ");

    const count = document.createElement("span");
    count.textContent = `${values.length} value${values.length === 1 ? "" : "s"}`;

    label.append(checkbox, name, count);

    const examples = document.createElement("small");
    examples.textContent = `Found: ${values.slice(0, 4).join(", ")}`;

    item.append(label, examples);
    findingsContainer.append(item);
  }
}

function selectedCategories() {
  return [...findingsContainer.querySelectorAll("input[type='checkbox']:checked")].map((box) => box.value);
}

function buildMapping(findings, categories) {
  const selected = new Set(categories);
  const mapping = new Map();

  for (const category of Object.keys(patterns)) {
    if (!selected.has(category)) continue;
    findings[category]?.forEach((value, index) => {
      if (!mapping.has(value)) {
        mapping.set(value, fakeValue[category](index + 1));
      }
    });
  }

  return [...mapping.entries()].sort((left, right) => right[0].length - left[0].length);
}

function sanitize(text, mapping) {
  return mapping.reduce((result, [realValue, replacement]) => result.split(realValue).join(replacement), text);
}

function updateStatus(message) {
  statusBox.textContent = message;
}

document.querySelector("#detect-button").addEventListener("click", () => {
  currentFindings = detect(sourceText.value);
  renderFindings(currentFindings);
  const total = Object.values(currentFindings).reduce((sum, values) => sum + values.length, 0);
  updateStatus(total ? `Detected ${total} unique sensitive-looking value${total === 1 ? "" : "s"}.` : "No obvious sensitive values detected.");
});

document.querySelector("#select-all-button").addEventListener("click", () => {
  findingsContainer.querySelectorAll("input[type='checkbox']").forEach((box) => {
    box.checked = true;
  });
});

document.querySelector("#clear-button").addEventListener("click", () => {
  sourceText.value = "";
  outputText.value = "";
  fileInput.value = "";
  currentFindings = {};
  renderFindings(currentFindings);
  findingsContainer.textContent = "No findings yet.";
  updateStatus("Paste text or load a file to begin.");
});

document.querySelector("#sanitize-button").addEventListener("click", () => {
  if (!Object.keys(currentFindings).length) {
    currentFindings = detect(sourceText.value);
    renderFindings(currentFindings);
  }

  const mapping = buildMapping(currentFindings, selectedCategories());
  outputText.value = sanitize(sourceText.value, mapping);
  updateStatus(mapping.length ? `Sanitized ${mapping.length} unique value${mapping.length === 1 ? "" : "s"}.` : "No categories selected. Nothing changed.");
});

fileInput.addEventListener("change", async () => {
  const [file] = fileInput.files;
  if (!file) return;
  sourceText.value = await file.text();
  outputText.value = "";
  currentFindings = detect(sourceText.value);
  renderFindings(currentFindings);
  updateStatus(`Loaded ${file.name} and detected ${Object.values(currentFindings).flat().length} unique value(s).`);
});

document.querySelector("#copy-button").addEventListener("click", async () => {
  if (!outputText.value) return;
  await navigator.clipboard.writeText(outputText.value);
  updateStatus("Sanitized output copied to clipboard.");
});

document.querySelector("#download-button").addEventListener("click", () => {
  if (!outputText.value) return;
  const blob = new Blob([outputText.value], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "sanitized-log.txt";
  link.click();
  URL.revokeObjectURL(url);
});
