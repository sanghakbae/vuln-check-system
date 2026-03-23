const { DEFAULT_PORT, SCAN_IGNORE_TLS_ERRORS } = require("./config");
const { startServer } = require("./httpServer");

if (SCAN_IGNORE_TLS_ERRORS) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  console.warn("TLS certificate verification is disabled for outbound scan requests.");
}

startServer(DEFAULT_PORT);
