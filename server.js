const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const ROOT = __dirname;
const DOMAINS_FILE = path.join(ROOT, "domains.json");
const SCAN_RESULTS_FILE = path.join(ROOT, "scan-results.json");
const CONFIG_FILE = path.join(ROOT, "config.local.json");
const LOCAL_CONFIG = readLocalConfig();
const HOST = "127.0.0.1";
const DEFAULT_PORT = Number(process.env.PORT || LOCAL_CONFIG.port || 3000);
const SPREADSHEET_WEBHOOK_URL =
  process.env.SPREADSHEET_WEBHOOK_URL || LOCAL_CONFIG.spreadsheetWebhookUrl || "";
const CRAWL_DELAY_MS = Number(process.env.CRAWL_DELAY_MS || LOCAL_CONFIG.crawlDelayMs || 900);
const PATH_CHECK_DELAY_MS = Number(process.env.PATH_CHECK_DELAY_MS || LOCAL_CONFIG.pathCheckDelayMs || 350);
const MAX_CRAWL_PAGES = Number(process.env.MAX_CRAWL_PAGES || LOCAL_CONFIG.maxCrawlPages || 48);
const MAX_SCRIPT_ASSETS = Number(process.env.MAX_SCRIPT_ASSETS || LOCAL_CONFIG.maxScriptAssets || 24);
const MAX_CRAWL_DEPTH = Number(process.env.MAX_CRAWL_DEPTH || LOCAL_CONFIG.maxCrawlDepth || 4);
const MAX_BROWSER_PAGES = Number(process.env.MAX_BROWSER_PAGES || LOCAL_CONFIG.maxBrowserPages || 20);
const clients = new Set();
let reloadVersion = Date.now();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-cache",
  });
  res.end(JSON.stringify(payload));
}

function readLocalConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function readLocalDomains() {
  try {
    const raw = fs.readFileSync(DOMAINS_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function writeLocalDomains(items) {
  fs.writeFileSync(DOMAINS_FILE, JSON.stringify(items, null, 2));
}

function readLocalScanResults() {
  try {
    const raw = fs.readFileSync(SCAN_RESULTS_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function writeLocalScanResults(items) {
  fs.writeFileSync(SCAN_RESULTS_FILE, JSON.stringify(items, null, 2));
}

async function listDomains() {
  if (!SPREADSHEET_WEBHOOK_URL) {
    return readLocalDomains();
  }

  const url = new URL(SPREADSHEET_WEBHOOK_URL);
  url.searchParams.set("action", "list");
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`spreadsheet_read_failed:${response.status}`);
  }

  const payload = await response.json();
  return Array.isArray(payload.items) ? payload.items : [];
}

async function upsertDomain(item) {
  if (!SPREADSHEET_WEBHOOK_URL) {
    const items = readLocalDomains();
    const index = items.findIndex((entry) => String(entry.id) === String(item.id));
    if (index === -1) {
      items.push(item);
    } else {
      items[index] = item;
    }
    writeLocalDomains(items);
    return item;
  }

  const response = await fetch(SPREADSHEET_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      action: "upsert",
      item,
    }),
  });

  if (!response.ok) {
    throw new Error(`spreadsheet_write_failed:${response.status}`);
  }

  return item;
}

async function listScans() {
  if (!SPREADSHEET_WEBHOOK_URL) {
    return readLocalScanResults();
  }

  const url = new URL(SPREADSHEET_WEBHOOK_URL);
  url.searchParams.set("action", "listScans");
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`spreadsheet_scan_read_failed:${response.status}`);
  }

  const payload = await response.json();
  return Array.isArray(payload.items) ? payload.items : [];
}

async function upsertScanResult(item) {
  if (!SPREADSHEET_WEBHOOK_URL) {
    const items = readLocalScanResults();
    const index = items.findIndex((entry) => String(entry.domain) === String(item.domain));
    if (index === -1) {
      items.push(item);
    } else {
      items[index] = item;
    }
    writeLocalScanResults(items);
    return item;
  }

  const response = await fetch(SPREADSHEET_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      action: "upsertScan",
      item,
    }),
  });

  if (!response.ok) {
    throw new Error(`spreadsheet_scan_write_failed:${response.status}`);
  }

  return item;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function pickHeader(headers, key) {
  return headers.get(key) || "없음";
}

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/\s+/g, " ").trim() : "없음";
}

function wait(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function buildScanHeaders(sessionValue, extras = {}) {
  const headers = {
    "User-Agent": "VulnCheckLocalScanner/0.1",
    ...extras,
  };

  if (sessionValue) {
    headers.Cookie = sessionValue;
  }

  return headers;
}

function isLikelyHtmlPage(targetUrl) {
  const pathname = targetUrl.pathname.toLowerCase();
  if (!pathname || pathname.endsWith("/")) {
    return true;
  }

  return !/\.(css|js|json|png|jpg|jpeg|gif|svg|ico|pdf|zip|txt|xml|woff2?)$/i.test(pathname);
}

function extractMatches(pattern, html) {
  return [...html.matchAll(pattern)].map((match) => match[1]).filter(Boolean);
}

function normalizeEndpoint(targetUrl) {
  const query = targetUrl.search || "";
  return `${targetUrl.pathname}${query}`;
}

function collectQueryParams(targetUrl) {
  return [...targetUrl.searchParams.keys()];
}

function normalizeDynamicSegment(segment) {
  if (!segment) {
    return segment;
  }

  if (/^\d+$/.test(segment)) {
    return ":id";
  }

  if (/^[0-9a-f]{8,}$/i.test(segment)) {
    return ":token";
  }

  if (/^[A-Za-z0-9_-]{16,}$/.test(segment)) {
    return ":value";
  }

  return segment;
}

function normalizePatternPath(pathname) {
  const segments = pathname.split("/").map((segment) => normalizeDynamicSegment(segment));
  return segments.join("/") || "/";
}

function extractFormBlocks(html) {
  return [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)].map((match) => ({
    attrs: match[1] || "",
    body: match[2] || "",
  }));
}

function extractAttr(source, attrName) {
  const match = source.match(new RegExp(`${attrName}\\s*=\\s*["']([^"']+)["']`, "i"));
  return match ? match[1] : "";
}

function extractScriptBlocks(html) {
  return [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].map((match) => ({
    attrs: match[1] || "",
    body: match[2] || "",
  }));
}

function extractUrlCandidates(html) {
  const candidates = new Set();
  const patterns = [
    /<(?:a|link)\b[^>]*href=["']([^"']+)["']/gi,
    /<(?:script|img|iframe|source)\b[^>]*src=["']([^"']+)["']/gi,
    /<form\b[^>]*action=["']([^"']+)["']/gi,
    /\b(?:data-href|data-url|data-src|data-link)=["']([^"']+)["']/gi,
    /<meta\b[^>]*http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"';]+)[^"']*["']/gi,
    /(?:location\.href|location\.assign|location\.replace|window\.open)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
  ];

  patterns.forEach((pattern) => {
    for (const match of html.matchAll(pattern)) {
      if (match[1]) {
        candidates.add(match[1]);
      }
    }
  });

  return [...candidates];
}

function extractJsCandidates(scriptBody) {
  const endpoints = [];
  const parameters = new Set();
  const endpointPatterns = [
    /(?:fetch|axios\.(?:get|post|put|delete|patch)|axios)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    /(?:url|path|endpoint)\s*:\s*["'`]([^"'`]+)["'`]/gi,
    /(?:location\.href|location\.assign|location\.replace)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    /["'`]((?:\/|\.\.?\/)[^"'`?\s]+(?:\?[^"'`\s]*)?)["'`]/gi,
  ];

  endpointPatterns.forEach((pattern) => {
    for (const match of scriptBody.matchAll(pattern)) {
      if (match[1]) {
        endpoints.push(match[1]);
      }
    }
  });

  for (const match of scriptBody.matchAll(/[\?&]([A-Za-z0-9_.-]+)=/g)) {
    if (match[1]) {
      parameters.add(match[1]);
    }
  }

  for (const match of scriptBody.matchAll(/["'`]([A-Za-z0-9_.-]+)["'`]\s*:/g)) {
    const key = match[1];
    if (
      !/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Accept|Content-Type)$/i.test(key) &&
      /^[A-Za-z][A-Za-z0-9_]{1,31}$/.test(key) &&
      !/^(v\d+_|webpack|chunk|middleware|__|build|runtime|assets?|locale|lang|theme|color|size|width|height)$/i.test(key)
    ) {
      parameters.add(key);
    }
  }

  return {
    endpoints,
    parameters: [...parameters],
  };
}

function addEndpointRecord(store, endpointUrl, method, source, params = []) {
  const key = `${method} ${endpointUrl}`;
  if (!store.has(key)) {
    store.set(key, {
      method,
      url: endpointUrl,
      source,
      params: new Set(),
    });
  }

  const current = store.get(key);
  params.forEach((param) => {
    if (param) {
      current.params.add(param);
    }
  });
}

function addParameterRecord(store, name, source, endpointUrl) {
  if (!name) {
    return;
  }

  if (
    !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(name) ||
    /^(v\d+_|webpack|chunk|middleware|__|runtime|build|locale|lang|theme|color|size|width|height)$/i.test(name)
  ) {
    return;
  }

  if (!store.has(name)) {
    store.set(name, {
      name,
      sources: new Set(),
      endpoints: new Set(),
    });
  }

  const current = store.get(name);
  current.sources.add(source);
  if (endpointUrl) {
    current.endpoints.add(endpointUrl);
  }
}

function mergeInventory(base, extra) {
  if (!extra) {
    return base;
  }

  const endpointStore = new Map();
  const parameterStore = new Map();
  const pageStore = new Map();
  const titleStore = new Set([...(base.titles || []), ...(extra.titles || [])]);
  const scriptStore = new Set([...(base.scripts || []), ...(extra.scripts || [])]);

  [...(base.pages || []), ...(extra.pages || [])].forEach((item) => {
    if (item?.url) {
      pageStore.set(item.url, item);
    }
  });

  [...(base.endpoints || []), ...(extra.endpoints || [])].forEach((item) => {
    if (!item?.url || !item?.method) {
      return;
    }
    addEndpointRecord(endpointStore, item.url, item.method, item.source || "merge", item.params || []);
  });

  [...(base.parameters || []), ...(extra.parameters || [])].forEach((item) => {
    if (!item?.name) {
      return;
    }
    addParameterRecord(parameterStore, item.name, (item.sources || [item.source || "merge"]).join("/"), "");
    const current = parameterStore.get(item.name);
    (item.sources || []).forEach((source) => current.sources.add(source));
    (item.endpoints || []).forEach((endpoint) => current.endpoints.add(endpoint));
  });

  return {
    pages: [...pageStore.values()],
    titles: [...titleStore],
    endpoints: [...endpointStore.values()].map((item) => ({
      method: item.method,
      url: item.url,
      source: item.source,
      params: [...item.params],
    })),
    parameters: [...parameterStore.values()].map((item) => ({
      name: item.name,
      sources: [...item.sources],
      endpoints: [...item.endpoints],
    })),
    scripts: [...scriptStore],
  };
}

function parseCookieHeader(sessionValue, targetUrl) {
  if (!sessionValue) {
    return [];
  }

  return sessionValue
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const [name, ...rest] = item.split("=");
      const value = rest.join("=");
      if (!name || !value) {
        return null;
      }

      return {
        name: name.trim(),
        value: value.trim(),
        domain: targetUrl.hostname,
        path: "/",
        httpOnly: false,
        secure: targetUrl.protocol === "https:",
        sameSite: "Lax",
      };
    })
    .filter(Boolean);
}

async function crawlInventoryWithBrowser(rootUrl, sessionValue) {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent: "VulnCheckBrowserCrawler/0.1",
  });
  const cookies = parseCookieHeader(sessionValue, rootUrl);
  if (cookies.length) {
    await context.addCookies(cookies);
  }

  const endpointStore = new Map();
  const parameterStore = new Map();
  const pageStore = new Map();
  const titleStore = new Set();
  const scriptStore = new Set();
  const requestStore = new Set();
  const queue = [{ url: rootUrl.toString(), depth: 0 }];
  const visited = new Set();

  try {
    while (queue.length && pageStore.size < MAX_BROWSER_PAGES) {
      const current = queue.shift();
      if (!current || visited.has(current.url) || current.depth > MAX_CRAWL_DEPTH) {
        continue;
      }
      visited.add(current.url);

      const page = await context.newPage();
      const pageRequests = [];
      page.on("request", (request) => {
        pageRequests.push(request.url());
      });

      try {
        await wait(CRAWL_DELAY_MS);
        await page.goto(current.url, { waitUntil: "domcontentloaded", timeout: 20000 });
        await page.waitForLoadState("networkidle", { timeout: 3000 }).catch(() => {});
        const pageUrl = new URL(page.url());
        if (pageUrl.origin !== rootUrl.origin) {
          await page.close();
          continue;
        }

        const html = await page.content();
        const title = await page.title();
        const pageEndpoint = normalizeEndpoint(pageUrl);
        const pagePattern = normalizePatternPath(pageUrl.pathname);
        const pageParams = collectQueryParams(pageUrl);
        addEndpointRecord(endpointStore, pageEndpoint, "GET", "browser-page", pageParams);
        if (pagePattern && pagePattern !== pageUrl.pathname) {
          addEndpointRecord(endpointStore, `${pagePattern}${pageUrl.search}`, "GET", "path-pattern", pageParams);
        }
        pageParams.forEach((param) => addParameterRecord(parameterStore, param, "browser-query", pageEndpoint));
        pageStore.set(pageEndpoint, { url: pageEndpoint, pattern: pagePattern, status: 200 });
        if (title) {
          titleStore.add(title);
        }

        const snapshot = await page.evaluate(() => {
          const links = [...document.querySelectorAll("a[href], [data-href], [data-url], [data-link]")]
            .map((node) => node.getAttribute("href") || node.getAttribute("data-href") || node.getAttribute("data-url") || node.getAttribute("data-link"))
            .filter(Boolean);
          const forms = [...document.querySelectorAll("form")].map((form) => ({
            action: form.getAttribute("action") || location.pathname,
            method: (form.getAttribute("method") || "GET").toUpperCase(),
            fields: [...form.querySelectorAll("input[name], textarea[name], select[name]")].map((field) => field.getAttribute("name")).filter(Boolean),
          }));
          const scriptSrcs = [...document.querySelectorAll("script[src]")].map((script) => script.getAttribute("src")).filter(Boolean);
          return { links, forms, scriptSrcs };
        });

        snapshot.links.forEach((href) => {
          try {
            const linkUrl = new URL(href, pageUrl);
            if (linkUrl.origin !== rootUrl.origin) {
              return;
            }
            const endpointUrl = normalizeEndpoint(linkUrl);
            const params = collectQueryParams(linkUrl);
            addEndpointRecord(endpointStore, endpointUrl, "GET", "browser-link", params);
            params.forEach((param) => addParameterRecord(parameterStore, param, "browser-query", endpointUrl));
            if (isLikelyHtmlPage(linkUrl) && !visited.has(linkUrl.toString())) {
              queue.push({ url: linkUrl.toString(), depth: current.depth + 1 });
            }
          } catch {
            return;
          }
        });

        snapshot.forms.forEach((form) => {
          try {
            const actionUrl = new URL(form.action, pageUrl);
            if (actionUrl.origin !== rootUrl.origin) {
              return;
            }
            const endpointUrl = normalizeEndpoint(actionUrl);
            addEndpointRecord(endpointStore, endpointUrl, form.method, "browser-form", form.fields);
            form.fields.forEach((field) => addParameterRecord(parameterStore, field, "browser-form", endpointUrl));
          } catch {
            return;
          }
        });

        snapshot.scriptSrcs.forEach((src) => {
          try {
            const scriptUrl = new URL(src, pageUrl);
            if (scriptUrl.origin === rootUrl.origin) {
              scriptStore.add(normalizeEndpoint(scriptUrl));
            }
          } catch {
            return;
          }
        });

        pageRequests.forEach((requestUrl) => {
          try {
            const request = new URL(requestUrl);
            if (request.origin !== rootUrl.origin) {
              return;
            }
            const endpointUrl = normalizeEndpoint(request);
            if (requestStore.has(endpointUrl)) {
              return;
            }
            requestStore.add(endpointUrl);
            const params = collectQueryParams(request);
            addEndpointRecord(endpointStore, endpointUrl, "GET", "browser-network", params);
            params.forEach((param) => addParameterRecord(parameterStore, param, "browser-network", endpointUrl));
          } catch {
            return;
          }
        });

        const htmlCandidates = extractUrlCandidates(html);
        htmlCandidates.forEach((candidate) => {
          try {
            const candidateUrl = new URL(candidate, pageUrl);
            if (candidateUrl.origin !== rootUrl.origin) {
              return;
            }
            const endpointUrl = normalizeEndpoint(candidateUrl);
            const params = collectQueryParams(candidateUrl);
            addEndpointRecord(endpointStore, endpointUrl, "GET", "browser-html", params);
            params.forEach((param) => addParameterRecord(parameterStore, param, "browser-html", endpointUrl));
            if (isLikelyHtmlPage(candidateUrl) && !visited.has(candidateUrl.toString())) {
              queue.push({ url: candidateUrl.toString(), depth: current.depth + 1 });
            }
          } catch {
            return;
          }
        });
      } finally {
        await page.close().catch(() => {});
      }
    }

    return {
      pages: [...pageStore.values()],
      titles: [...titleStore],
      endpoints: [...endpointStore.values()].map((item) => ({
        method: item.method,
        url: item.url,
        source: item.source,
        params: [...item.params],
      })),
      parameters: [...parameterStore.values()].map((item) => ({
        name: item.name,
        sources: [...item.sources],
        endpoints: [...item.endpoints],
      })),
      scripts: [...scriptStore],
    };
  } finally {
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}

async function crawlInventory(rootUrl, rootHtml, sessionValue) {
  const queue = [{ url: rootUrl.toString(), depth: 0 }];
  const visited = new Set();
  const fetchedScripts = new Set();
  const endpointStore = new Map();
  const parameterStore = new Map();
  const crawledPages = [];
  const titles = [];
  const maxPages = Math.max(6, MAX_CRAWL_PAGES);
  const sameOrigin = rootUrl.origin;
  const htmlCache = new Map([[rootUrl.toString(), rootHtml]]);

  function queuePage(targetUrl, depth) {
    if (!targetUrl || visited.has(targetUrl) || depth > MAX_CRAWL_DEPTH) {
      return;
    }
    if (queue.some((item) => item.url === targetUrl)) {
      return;
    }
    queue.push({ url: targetUrl, depth });
  }

  while (queue.length && crawledPages.length < maxPages) {
    const currentJob = queue.shift();
    const currentUrl = currentJob?.url;
    const currentDepth = currentJob?.depth ?? 0;
    if (!currentUrl || visited.has(currentUrl)) {
      continue;
    }
    visited.add(currentUrl);

    let html = htmlCache.get(currentUrl);
    let status = 200;

    if (typeof html !== "string") {
      try {
        await wait(CRAWL_DELAY_MS);
        const response = await fetch(currentUrl, {
          method: "GET",
          redirect: "follow",
          headers: buildScanHeaders(sessionValue, {
            Accept: "text/html,application/xhtml+xml",
          }),
        });
        status = response.status;
        const contentType = response.headers.get("content-type") || "";
        if (!contentType.includes("text/html")) {
          continue;
        }
        html = await response.text();
      } catch {
        continue;
      }
    }

    const pageUrl = new URL(currentUrl);
    const pageEndpoint = normalizeEndpoint(pageUrl);
    const pagePattern = normalizePatternPath(pageUrl.pathname);
    const pageParams = collectQueryParams(pageUrl);
    addEndpointRecord(endpointStore, pageEndpoint, "GET", "page", pageParams);
    if (pagePattern && pagePattern !== pageUrl.pathname) {
      addEndpointRecord(endpointStore, `${pagePattern}${pageUrl.search}`, "GET", "path-pattern", pageParams);
    }
    pageParams.forEach((param) => addParameterRecord(parameterStore, param, "query", pageEndpoint));

    crawledPages.push({
      url: pageEndpoint,
      pattern: pagePattern,
      status,
    });

    const title = extractTitle(html);
    if (title && title !== "없음") {
      titles.push(title);
    }

    const links = extractMatches(/<a\b[^>]*href=["']([^"']+)["']/gi, html);
    links.forEach((href) => {
      try {
        const linkUrl = new URL(href, pageUrl);
        if (linkUrl.origin !== sameOrigin) {
          return;
        }
        const endpointUrl = normalizeEndpoint(linkUrl);
        const patternUrl = `${normalizePatternPath(linkUrl.pathname)}${linkUrl.search}`;
        const params = collectQueryParams(linkUrl);
        addEndpointRecord(endpointStore, endpointUrl, "GET", "link", params);
        if (patternUrl !== endpointUrl) {
          addEndpointRecord(endpointStore, patternUrl, "GET", "path-pattern", params);
        }
        params.forEach((param) => addParameterRecord(parameterStore, param, "query", endpointUrl));
        if (isLikelyHtmlPage(linkUrl)) {
          queuePage(linkUrl.toString(), currentDepth + 1);
        }
      } catch {
        return;
      }
    });

    extractUrlCandidates(html).forEach((candidate) => {
      try {
        const candidateUrl = new URL(candidate, pageUrl);
        if (candidateUrl.origin !== sameOrigin) {
          return;
        }

        const endpointUrl = normalizeEndpoint(candidateUrl);
        const params = collectQueryParams(candidateUrl);
        addEndpointRecord(endpointStore, endpointUrl, "GET", "html-attr", params);
        params.forEach((param) => addParameterRecord(parameterStore, param, "html-attr", endpointUrl));

        if (isLikelyHtmlPage(candidateUrl)) {
          queuePage(candidateUrl.toString(), currentDepth + 1);
        }
      } catch {
        return;
      }
    });

    extractFormBlocks(html).forEach((form) => {
      try {
        const action = extractAttr(form.attrs, "action") || pageUrl.pathname;
        const method = (extractAttr(form.attrs, "method") || "GET").toUpperCase();
        const actionUrl = new URL(action, pageUrl);
        if (actionUrl.origin !== sameOrigin) {
          return;
        }
        const fieldNames = extractMatches(/<(?:input|textarea|select)\b[^>]*name=["']([^"']+)["']/gi, form.body);
        const endpointUrl = normalizeEndpoint(actionUrl);
        addEndpointRecord(endpointStore, endpointUrl, method, "form", fieldNames);
        fieldNames.forEach((field) => addParameterRecord(parameterStore, field, "form", endpointUrl));
      } catch {
        return;
      }
    });

    extractScriptBlocks(html).forEach((script) => {
      const src = extractAttr(script.attrs, "src");
      if (src) {
        try {
          const srcUrl = new URL(src, pageUrl);
          if (srcUrl.origin === sameOrigin) {
            const normalizedScriptUrl = normalizeEndpoint(srcUrl);
            addEndpointRecord(endpointStore, normalizedScriptUrl, "GET", "script-src", collectQueryParams(srcUrl));
            if (fetchedScripts.size < MAX_SCRIPT_ASSETS && !fetchedScripts.has(srcUrl.toString())) {
              fetchedScripts.add(srcUrl.toString());
            }
          }
        } catch {
          return;
        }
      }

      const jsCandidates = extractJsCandidates(script.body);
      jsCandidates.endpoints.forEach((candidate) => {
        try {
          const candidateUrl = new URL(candidate, pageUrl);
          if (candidateUrl.origin !== sameOrigin) {
            return;
          }
          const endpointUrl = normalizeEndpoint(candidateUrl);
          const params = collectQueryParams(candidateUrl);
          addEndpointRecord(endpointStore, endpointUrl, "GET", "script-inline", params);
          const patternUrl = `${normalizePatternPath(candidateUrl.pathname)}${candidateUrl.search}`;
          if (patternUrl !== endpointUrl) {
            addEndpointRecord(endpointStore, patternUrl, "GET", "path-pattern", params);
          }
          params.forEach((param) => addParameterRecord(parameterStore, param, "script-query", endpointUrl));
          if (isLikelyHtmlPage(candidateUrl)) {
            queuePage(candidateUrl.toString(), currentDepth + 1);
          }
        } catch {
          return;
        }
      });

      jsCandidates.parameters.forEach((param) => {
        addParameterRecord(parameterStore, param, "script-body", pageEndpoint);
      });
    });
  }

  for (const scriptUrlText of fetchedScripts) {
    try {
      await wait(CRAWL_DELAY_MS);
      const scriptUrl = new URL(scriptUrlText);
      const response = await fetch(scriptUrl, {
        method: "GET",
        redirect: "follow",
        headers: buildScanHeaders(sessionValue, {
          Accept: "application/javascript,text/javascript,*/*;q=0.8",
        }),
      });

      if (!response.ok) {
        continue;
      }

      const body = await response.text();
      const jsCandidates = extractJsCandidates(body);
      const scriptEndpoint = normalizeEndpoint(scriptUrl);

      jsCandidates.endpoints.forEach((candidate) => {
        try {
          const candidateUrl = new URL(candidate, scriptUrl);
          if (candidateUrl.origin !== sameOrigin) {
            return;
          }

          const endpointUrl = normalizeEndpoint(candidateUrl);
          const params = collectQueryParams(candidateUrl);
          addEndpointRecord(endpointStore, endpointUrl, "GET", "script-asset", params);
          const patternUrl = `${normalizePatternPath(candidateUrl.pathname)}${candidateUrl.search}`;
          if (patternUrl !== endpointUrl) {
            addEndpointRecord(endpointStore, patternUrl, "GET", "path-pattern", params);
          }
          params.forEach((param) => addParameterRecord(parameterStore, param, "script-asset-query", endpointUrl));
        } catch {
          return;
        }
      });

      jsCandidates.parameters.forEach((param) => {
        addParameterRecord(parameterStore, param, "script-asset-body", scriptEndpoint);
      });
    } catch {
      continue;
    }
  }

  return {
    pages: crawledPages,
    titles,
    endpoints: [...endpointStore.values()].map((item) => ({
      method: item.method,
      url: item.url,
      source: item.source,
      params: [...item.params],
    })),
    parameters: [...parameterStore.values()].map((item) => ({
      name: item.name,
      sources: [...item.sources],
      endpoints: [...item.endpoints],
    })),
    scripts: [...fetchedScripts],
  };
}

async function runBasicScan(target, sessionValue = "") {
  const url = new URL(target);
  const response = await fetch(url, {
    method: "GET",
    redirect: "follow",
    headers: buildScanHeaders(sessionValue, {
      Accept: "text/html,application/xhtml+xml",
    }),
  });
  const html = await response.text();
  const staticInventory = await crawlInventory(url, html, sessionValue);
  const browserInventory = await crawlInventoryWithBrowser(url, sessionValue).catch(() => null);
  const inventory = mergeInventory(staticInventory, browserInventory);

  const headers = response.headers;
  const securityHeaders = [
    ["Content-Security-Policy", pickHeader(headers, "content-security-policy")],
    ["Strict-Transport-Security", pickHeader(headers, "strict-transport-security")],
    ["X-Frame-Options", pickHeader(headers, "x-frame-options")],
    ["X-Content-Type-Options", pickHeader(headers, "x-content-type-options")],
  ];

  const pathsToCheck = ["/login", "/admin", "/robots.txt", "/sitemap.xml", "/api/docs"];
  const pathChecks = [];
  for (const pathname of pathsToCheck) {
    try {
      await wait(PATH_CHECK_DELAY_MS);
      const pathUrl = new URL(pathname, url);
      const pathResponse = await fetch(pathUrl, {
        method: "GET",
        redirect: "manual",
        headers: buildScanHeaders(sessionValue),
      });
      pathChecks.push({
        path: pathname,
        status: pathResponse.status,
        ok: pathResponse.status < 400,
      });
    } catch {
      pathChecks.push({
        path: pathname,
        status: "error",
        ok: false,
      });
    }
  }

  const openPaths = pathChecks.filter((item) => item.ok).map((item) => `${item.path} (${item.status})`);
  const serverHeader = pickHeader(headers, "server");
  const poweredBy = pickHeader(headers, "x-powered-by");
  const pageTitle = extractTitle(html);
  const linkCount = (html.match(/<a\b/gi) || []).length;
  const scriptCount = (html.match(/<script\b/gi) || []).length;
  const formCount = (html.match(/<form\b/gi) || []).length;
  const scriptAssetCount = inventory.scripts?.length || 0;
  const patternCount = inventory.pages.filter((item) => item.pattern && item.pattern !== new URL(item.url, url).pathname).length;
  const stackText =
    [poweredBy !== "없음" ? poweredBy : "", serverHeader !== "없음" ? serverHeader : ""].filter(Boolean).join(" / ") ||
    "추정 불가";

  return {
    target,
    response: {
      status: response.status,
      finalUrl: response.url,
      https: url.protocol === "https:",
      sessionUsed: Boolean(sessionValue),
    },
    page: {
      title: pageTitle,
      links: inventory.pages.length,
      scripts: scriptCount,
      forms: formCount,
    },
    inventory,
    headers: securityHeaders,
    paths: pathChecks,
    stack: {
      server: serverHeader,
      poweredBy,
    },
    openPaths,
    findings: [
      {
        label: "응답 상태",
        title: "기본 응답 확인",
        request: {
          method: "GET",
          url: target,
          headers: ["Accept: text/html,application/xhtml+xml", "User-Agent: VulnCheckLocalScanner/0.1"],
        },
        response: {
          status: response.status,
          headers: [`Final-URL: ${response.url}`],
          body: `HTTPS 사용 여부: ${url.protocol === "https:" ? "예" : "아니오"}`,
        },
        verdict: response.status < 400 ? "양호" : "확인 필요",
        evidence: `${response.url} 에서 기본 응답을 확인했습니다.`,
      },
      {
        label: "보안 헤더",
        title: "핵심 보안 헤더 점검",
        request: {
          method: "GET",
          url: target,
          headers: ["헤더 수집"],
        },
        response: {
          status: response.status,
          headers: securityHeaders.map(([name, value]) => `${name}: ${value}`),
          body: "핵심 응답 헤더 존재 여부를 확인했습니다.",
        },
        verdict: securityHeaders.some(([, value]) => value === "없음") ? "확인 필요" : "양호",
        evidence: securityHeaders
          .map(([name, value]) => `${name}: ${value === "없음" ? "없음" : "설정됨"}`)
          .join(" / "),
      },
      {
        label: "페이지 구조",
        title: "라이트 크롤링 요약",
        request: {
          method: "GET",
          url: target,
          headers: ["본문 파싱"],
        },
        response: {
          status: response.status,
          headers: [`Content-Type: ${pickHeader(headers, "content-type")}`],
          body: `Title: ${pageTitle} / 페이지 ${inventory.pages.length}개 / 인라인 스크립트 ${scriptCount}개 / 외부 JS ${scriptAssetCount}개 / 폼 ${formCount}개 / 패턴 ${patternCount}개`,
        },
        verdict: "정보",
        evidence: "링크, 폼, 인라인 스크립트, 외부 JS, 경로 패턴까지 순차 수집했습니다.",
      },
      {
        label: "파라미터 인벤토리",
        title: "수동 점검 후보 파라미터 저장",
        request: {
          method: "CRAWL",
          url: target,
          headers: ["링크 / 폼 / 쿼리 파라미터 수집"],
        },
        response: {
          status: 200,
          headers: [`Endpoints: ${inventory.endpoints.length}`, `Parameters: ${inventory.parameters.length}`],
          body: inventory.parameters.length
            ? inventory.parameters.map((item) => `${item.name} (${item.sources.join("/")})`).join(", ")
            : "query, form, inline-script 기준 수집된 파라미터 없음",
        },
        verdict: inventory.parameters.length ? "정보" : "확인 필요",
        evidence: "수동 점검에 활용할 URL, path pattern, 파라미터 인벤토리를 저장했습니다.",
      },
      {
        label: "공개 경로",
        title: "기본 경로 탐색",
        request: {
          method: "GET",
          url: target,
          headers: pathsToCheck.map((pathname) => `Path Probe: ${pathname}`),
        },
        response: {
          status: response.status,
          headers: pathChecks.map((item) => `${item.path}: ${item.status}`),
          body: openPaths.length ? openPaths.join(", ") : "주요 공개 경로는 별도 확인되지 않았습니다.",
        },
        verdict: openPaths.length ? "확인 필요" : "양호",
        evidence: openPaths.length ? "리다이렉트 또는 접근 가능한 공개 경로가 탐지되었습니다." : "기본 후보 경로는 별도 노출되지 않았습니다.",
      },
      {
        label: "기술 스택",
        title: "서버 헤더 기반 추정",
        request: {
          method: "GET",
          url: target,
          headers: ["응답 헤더 분석"],
        },
        response: {
          status: response.status,
          headers: [`Server: ${serverHeader}`, `X-Powered-By: ${poweredBy}`],
          body: stackText,
        },
        verdict: "정보",
        evidence: "서버 응답 헤더를 기준으로 기술 스택을 추정했습니다.",
      },
      {
        label: "추가 확인",
        title: "다음 수동 검증 후보",
        request: {
          method: "ANALYZE",
          url: target,
          headers: ["수집 결과 종합"],
        },
        response: {
          status: 200,
          headers: ["Manual Review Queue"],
          body: `로그인 폼 ${formCount ? "존재 가능" : "미탐지"}, 관리자 콘솔/문서 경로 노출 여부를 기준으로 후속 점검이 필요합니다.`,
        },
        verdict: "수동 점검",
        evidence: "자동 수집 결과를 바탕으로 수동 검증 우선순위를 정리했습니다.",
      },
    ],
  };
}

async function verifySessionState(target, sessionValue, checkPath) {
  const baseUrl = new URL(target);
  const verifyUrl = new URL(checkPath || "/admin", baseUrl);
  const response = await fetch(verifyUrl, {
    method: "GET",
    redirect: "follow",
    headers: buildScanHeaders(sessionValue, {
      Accept: "text/html,application/xhtml+xml",
    }),
  });

  const html = await response.text();
  const normalizedBody = html.toLowerCase();
  const finalUrl = response.url;
  const redirectedToLogin =
    finalUrl.toLowerCase().includes("/login") ||
    normalizedBody.includes("login") ||
    normalizedBody.includes("로그인");

  let verdict = "확인 필요";
  let reason = "응답은 있었지만 세션 유효 여부를 자동 확정하기 어렵습니다.";

  if (response.status >= 200 && response.status < 400 && !redirectedToLogin) {
    verdict = "유효";
    reason = "로그인 후 전용 페이지로 보이는 응답이 확인되었습니다.";
  } else if (redirectedToLogin || response.status === 401 || response.status === 403) {
    verdict = "무효";
    reason = "로그인 페이지 이동 또는 권한 부족 응답이 확인되었습니다.";
  }

  return {
    url: verifyUrl.toString(),
    finalUrl,
    status: response.status,
    verdict,
    reason,
  };
}

function liveReloadScript() {
  return `
    <script>
      (() => {
        const source = new EventSource("/__events");
        source.addEventListener("reload", () => window.location.reload());

        let currentVersion = null;
        const poll = async () => {
          try {
            const response = await fetch("/__version", { cache: "no-store" });
            const data = await response.json();
            if (currentVersion === null) {
              currentVersion = data.version;
              return;
            }
            if (currentVersion !== data.version) {
              window.location.reload();
            }
          } catch (_) {
          }
        };

        poll();
        setInterval(poll, 1000);
      })();
    </script>
  `;
}

function broadcastReload() {
  reloadVersion = Date.now();
  for (const client of clients) {
    client.write("event: reload\\n");
    client.write(`data: ${Date.now()}\\n\\n`);
  }
}

function sendFile(filePath, res) {
  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(error.code === "ENOENT" ? 404 : 500, {
        "Content-Type": "text/plain; charset=utf-8",
      });
      res.end(error.code === "ENOENT" ? "Not Found" : "Server Error");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    if (ext === ".html") {
      const html = data.toString("utf8").replace("</body>", `${liveReloadScript()}</body>`);
      res.writeHead(200, {
        "Content-Type": MIME_TYPES[ext],
        "Cache-Control": "no-cache",
      });
      res.end(html);
      return;
    }

    res.writeHead(200, {
      "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
      "Cache-Control": "no-cache",
    });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/api/domains") {
    listDomains()
      .then((items) => {
        sendJson(res, 200, { items });
      })
      .catch((error) => {
        sendJson(res, 500, {
          error: "domains_read_failed",
          message: error.message,
        });
      });
    return;
  }

  if (req.method === "POST" && req.url === "/api/domains") {
    readJson(req)
      .then(async (payload) => {
        const item = payload.item || {};
        if (!item.id || !item.domain) {
          sendJson(res, 400, {
            error: "invalid_domain_payload",
          });
          return;
        }

        const saved = await upsertDomain(item);
        sendJson(res, 200, { item: saved });
      })
      .catch((error) => {
        sendJson(res, 500, {
          error: "domains_write_failed",
          message: error.message,
        });
      });
    return;
  }

  if (req.method === "GET" && req.url === "/api/scans") {
    listScans()
      .then((items) => {
        sendJson(res, 200, { items });
      })
      .catch((error) => {
        sendJson(res, 500, {
          error: "scans_read_failed",
          message: error.message,
        });
      });
    return;
  }

  if (req.method === "POST" && req.url === "/api/scans") {
    readJson(req)
      .then(async (payload) => {
        const item = payload.item || {};
        if (!item.domain || !item.result) {
          sendJson(res, 400, {
            error: "invalid_scan_payload",
          });
          return;
        }

        const saved = await upsertScanResult(item);
        sendJson(res, 200, { item: saved });
      })
      .catch((error) => {
        sendJson(res, 500, {
          error: "scans_write_failed",
          message: error.message,
        });
      });
    return;
  }

  if (req.method === "POST" && req.url === "/api/scan") {
    readJson(req)
      .then(async (payload) => {
        const target = String(payload.target || "").trim();
        const sessionValue = String(payload.sessionValue || "").trim();
        if (!target) {
          sendJson(res, 400, { error: "target is required" });
          return;
        }

        try {
          const result = await runBasicScan(target, sessionValue);
          sendJson(res, 200, result);
        } catch (error) {
          sendJson(res, 500, {
            error: "scan_failed",
            message: error.message,
          });
        }
      })
      .catch((error) => {
        sendJson(res, 400, {
          error: "invalid_json",
          message: error.message,
        });
      });
    return;
  }

  if (req.method === "POST" && req.url === "/api/session-check") {
    readJson(req)
      .then(async (payload) => {
        const target = String(payload.target || "").trim();
        const sessionValue = String(payload.sessionValue || "").trim();
        const checkPath = String(payload.checkPath || "").trim();

        if (!target || !sessionValue) {
          sendJson(res, 400, {
            error: "invalid_session_check_payload",
            message: "target and sessionValue are required",
          });
          return;
        }

        const result = await verifySessionState(target, sessionValue, checkPath);
        sendJson(res, 200, result);
      })
      .catch((error) => {
        sendJson(res, 500, {
          error: "session_check_failed",
          message: error.message,
        });
      });
    return;
  }

  if (req.url === "/__version") {
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(JSON.stringify({ version: reloadVersion }));
    return;
  }

  if (req.url === "/__events") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    res.write("\n");

    clients.add(res);
    req.on("close", () => {
      clients.delete(res);
    });
    return;
  }

  const requestPath = req.url === "/" ? "/index.html" : req.url || "/index.html";
  const safePath = path.normalize(requestPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(ROOT, safePath);

  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Forbidden");
    return;
  }

  sendFile(filePath, res);
});

fs.watch(ROOT, { recursive: true }, (_, filename) => {
  if (!filename) {
    return;
  }

  if (filename.startsWith(".") || filename === "server.js") {
    return;
  }

  broadcastReload();
});

function startServer(port) {
  server
    .once("error", (error) => {
      if (error.code === "EADDRINUSE") {
        const nextPort = port + 1;
        console.log(`Port ${port} is already in use. Retrying on ${nextPort}...`);
        startServer(nextPort);
        return;
      }

      throw error;
    })
    .listen(port, HOST, () => {
      console.log(`Vuln-check running at http://${HOST}:${port}`);
    });
}

startServer(DEFAULT_PORT);
