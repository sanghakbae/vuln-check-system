const { DEFAULT_PORT } = require("./config");
const { startServer } = require("./httpServer");

startServer(DEFAULT_PORT);
