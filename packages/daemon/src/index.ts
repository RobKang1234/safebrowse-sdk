#!/usr/bin/env node
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { formatDaemonHelp, parseDaemonOptions, runDaemonCli } from "./cli.js";
import { createSafeBrowseServer, startSafeBrowseDaemon } from "./server.js";

export { formatDaemonHelp, parseDaemonOptions, runDaemonCli } from "./cli.js";
export { createSafeBrowseServer, startSafeBrowseDaemon } from "./server.js";

function isDirectExecution(): boolean {
  if (!process.argv[1]) {
    return false;
  }

  return fileURLToPath(import.meta.url) === resolve(process.argv[1]);
}

if (isDirectExecution()) {
  runDaemonCli().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    console.error(formatDaemonHelp());
    process.exitCode = 1;
  });
}
