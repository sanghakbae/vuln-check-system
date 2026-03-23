const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "../..");
const DOMAINS_FILE = path.join(ROOT, "domains.json");
const SCAN_RESULTS_FILE = path.join(ROOT, "scan-results.json");
const CONFIG_FILE = path.join(ROOT, "config.local.json");

function readLocalConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

const LOCAL_CONFIG = readLocalConfig();
const CORS_ORIGINS = String(process.env.CORS_ORIGINS || LOCAL_CONFIG.corsOrigins || "")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);

module.exports = {
  ROOT,
  DOMAINS_FILE,
  SCAN_RESULTS_FILE,
  CONFIG_FILE,
  LOCAL_CONFIG,
  HOST: "127.0.0.1",
  DEFAULT_PORT: Number(process.env.PORT || LOCAL_CONFIG.port || 3000),
  SPREADSHEET_WEBHOOK_URL: process.env.SPREADSHEET_WEBHOOK_URL || LOCAL_CONFIG.spreadsheetWebhookUrl || "",
  CORS_ORIGINS,
  CRAWL_DELAY_MS: Number(process.env.CRAWL_DELAY_MS || LOCAL_CONFIG.crawlDelayMs || 900),
  PATH_CHECK_DELAY_MS: Number(process.env.PATH_CHECK_DELAY_MS || LOCAL_CONFIG.pathCheckDelayMs || 350),
  MAX_CRAWL_PAGES: Number(process.env.MAX_CRAWL_PAGES || LOCAL_CONFIG.maxCrawlPages || 48),
  MAX_SCRIPT_ASSETS: Number(process.env.MAX_SCRIPT_ASSETS || LOCAL_CONFIG.maxScriptAssets || 24),
  MAX_CRAWL_DEPTH: Number(process.env.MAX_CRAWL_DEPTH || LOCAL_CONFIG.maxCrawlDepth || 4),
  MAX_BROWSER_PAGES: Number(process.env.MAX_BROWSER_PAGES || LOCAL_CONFIG.maxBrowserPages || 20),
};
