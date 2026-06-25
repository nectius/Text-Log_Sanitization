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

const defaultExampleLogs = '--------EXAMPLE LOGS------------\n\n--- examples/network.log ---\n2026-06-24T08:15:42Z netflow host=edge-router-nyc01.example-corp.local src_ip=10.42.18.25 src_mac=00:16:3e:7a:91:02 src_user=EXAMPLECORP\\\\jdoe dst_ip=203.0.113.45 dst_domain=api.partner-demo.net dst_port=443 proto=TCP bytes_out=18422 bytes_in=92718 sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n2026-06-24T08:16:03Z dns host=dns-cache-02.example-corp.local client_ip=10.42.18.25 client_mac=00:16:3e:7a:91:02 user=jdoe@example-corp.local query=updates.example-tools.org answer=198.51.100.77 record=A action=allowed\n2026-06-24T08:17:11Z proxy host=proxy-west-01.example-corp.local user=asmith@example-corp.local client_ip=10.42.22.91 client_mac=52:54:00:ab:cd:10 method=GET url=https://downloads.example-tools.org/agent/v4/installer.msi dst_ip=198.51.100.77 status=200 md5=5d41402abc4b2a76b9719d911017c592\n2026-06-24T08:18:29Z vpn host=vpn-gw-01.example-corp.local event=login_success user=mgarcia@example-corp.local email=maria.garcia@example.com assigned_ip=10.99.4.18 public_ip=192.0.2.144 device_mac=3c:22:fb:5a:19:aa hostname=LAPTOP-MGARCIA\n\n--- examples/endpoint.log ---\n2026-06-24T09:02:14Z endpoint host=WKSTN-FIN-014.example-corp.local ip=10.42.33.14 mac=08:00:27:12:34:56 user=EXAMPLECORP\\\\lchen event=process_start image=C:\\\\Program Files\\\\ExampleApp\\\\exampleapp.exe command="exampleapp.exe --sync reports.example-finance.test" parent=explorer.exe sha1=2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n2026-06-24T09:03:50Z endpoint host=WKSTN-FIN-014.example-corp.local ip=10.42.33.14 mac=08:00:27:12:34:56 user=linda.chen@example.com event=file_write path=C:\\\\Users\\\\lchen\\\\Downloads\\\\invoice-review.xlsm sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 source_url=https://files.vendor-demo.example/invoice-review.xlsm\n2026-06-24T09:05:22Z endpoint host=MACBOOK-OPS-07.example-corp.local ip=10.42.41.7 mac=f0:18:98:44:21:0c user=ops_admin@example-corp.local event=usb_insert vendor=ExampleStorage serial=EXUSB-2026-00017 volume=/Volumes/DEMO_BACKUP\n\n--- examples/sysmon.log ---\n2026-06-24 10:10:02 Sysmon EventID=1 Computer=SRV-APP-03.example-corp.local User=EXAMPLECORP\\\\svc_deploy Image=C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe CommandLine="powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\\\Deploy\\\\healthcheck.ps1" ParentImage=C:\\\\Windows\\\\System32\\\\cmd.exe ProcessGuid={11111111-2222-3333-4444-555555555555} Hashes=SHA256=7d793037a0760186574b0282f2f435e7\n2026-06-24 10:11:47 Sysmon EventID=3 Computer=SRV-APP-03.example-corp.local User=EXAMPLECORP\\\\svc_deploy SourceIp=10.42.50.23 SourcePort=49822 DestinationIp=198.51.100.25 DestinationHostname=repo.packages-demo.net DestinationPort=443 Protocol=tcp Image=C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\n2026-06-24 10:12:19 Sysmon EventID=11 Computer=SRV-APP-03.example-corp.local User=EXAMPLECORP\\\\svc_deploy TargetFilename=C:\\\\Deploy\\\\packages\\\\web-agent.zip Hashes=MD5=098f6bcd4621d373cade4e832627b4f6,SHA1=a9993e364706816aba3e25717850c26c9cd0d89d\n\n--- examples/firewall.log ---\n2026-06-24T11:20:01Z firewall=fw-edge-01.example-corp.local action=allow rule=OUTBOUND_HTTPS src=10.42.18.25 src_port=53144 src_user=jdoe@example-corp.local src_mac=00:16:3e:7a:91:02 dst=203.0.113.10 dst_port=443 dst_domain=portal.customer-demo.example app=tls bytes=64122\n2026-06-24T11:21:33Z firewall=fw-edge-01.example-corp.local action=deny rule=BLOCK_SSH_INBOUND src=198.51.100.200 src_port=44771 dst=192.0.2.25 dst_port=22 dst_hostname=bastion-demo.example-corp.local reason=policy mac=00:25:96:ff:ee:10\n2026-06-24T11:22:08Z firewall=fw-dc-02.example-corp.local action=allow rule=DNS_TO_RESOLVER src=10.42.60.8 src_hostname=SRV-DB-02.example-corp.local src_mac=00:50:56:9a:2b:3c dst=10.42.1.53 dst_hostname=dns01.example-corp.local dst_port=53 domain=telemetry.example-db.test user=EXAMPLECORP\\\\svc_sql\n\n--- examples/powershell.log ---\n2026-06-24T12:30:14Z PowerShell host=ADMIN-JUMP-01.example-corp.local user=EXAMPLECORP\\\\admin.rivera email=admin.rivera@example-corp.local event=ScriptBlockText script="Invoke-WebRequest -Uri https://repo.admin-demo.example/tools/audit.ps1 -OutFile C:\\\\Temp\\\\audit.ps1" source_ip=10.42.70.5 mac=00:0c:29:aa:bb:cc sha256=3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7\n2026-06-24T12:31:02Z PowerShell host=ADMIN-JUMP-01.example-corp.local user=EXAMPLECORP\\\\admin.rivera event=CommandInvocation command="Get-ADUser -Filter * -Properties mail" domain=example-corp.local dc_ip=10.42.1.10 output_mail=helpdesk@example-corp.local\n2026-06-24T12:32:45Z PowerShell host=WKSTN-HR-022.example-corp.local user=EXAMPLECORP\\\\npatel event=ModuleLoad module=Microsoft.PowerShell.Management image_hash=1f3870be274f6c49b3e31a0c6728957f client_ip=10.42.44.22 client_mac=ac:de:48:00:11:22\n';

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

function loadDefaultExampleLogs() {
  if (sourceText.value.trim()) return;
  sourceText.value = defaultExampleLogs;
  currentFindings = detect(sourceText.value);
  renderFindings(currentFindings);
  const total = Object.values(currentFindings).reduce((sum, values) => sum + values.length, 0);
  updateStatus(`Loaded example logs and detected ${total} unique sensitive-looking value${total === 1 ? "" : "s"}.`);
}

loadDefaultExampleLogs();
