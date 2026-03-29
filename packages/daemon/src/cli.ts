import { resolve } from "node:path";
import process from "node:process";

import { startSafeBrowseDaemon, type SafeBrowseDaemonOptions } from "./server.js";

export interface ParsedDaemonOptions extends SafeBrowseDaemonOptions {
  help?: boolean;
}

const HELP_TEXT = `SafeBrowse daemon

Usage:
  safebrowse-daemon [--host 127.0.0.1] [--port 8787] [--root-dir <path>]

Environment:
  SAFEBROWSE_HOST
  SAFEBROWSE_PORT
  SAFEBROWSE_ROOT_DIR
`;

function parsePort(value: string): number {
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    throw new Error(`Invalid port: ${value}`);
  }
  return port;
}

export function formatDaemonHelp(): string {
  return HELP_TEXT;
}

export function parseDaemonOptions(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env
): ParsedDaemonOptions {
  const options: ParsedDaemonOptions = {};
  const queue = [...argv];

  const envHost = env.SAFEBROWSE_HOST?.trim();
  const envPort = env.SAFEBROWSE_PORT?.trim();
  const envRootDir = env.SAFEBROWSE_ROOT_DIR?.trim();

  if (envHost) {
    options.host = envHost;
  }
  if (envPort) {
    options.port = parsePort(envPort);
  }
  if (envRootDir) {
    options.rootDir = resolve(envRootDir);
  }

  while (queue.length > 0) {
    const arg = queue.shift();
    if (!arg) {
      continue;
    }

    if (arg === "--help" || arg === "-h") {
      options.help = true;
      continue;
    }

    if (arg === "--host") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --host");
      }
      options.host = value;
      continue;
    }

    if (arg === "--port") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --port");
      }
      options.port = parsePort(value);
      continue;
    }

    if (arg === "--root-dir") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --root-dir");
      }
      options.rootDir = resolve(value);
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return options;
}

export async function runDaemonCli(
  argv: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env
): Promise<void> {
  const options = parseDaemonOptions(argv, env);
  if (options.help) {
    console.log(formatDaemonHelp());
    return;
  }

  const server = await startSafeBrowseDaemon(options);
  const address = server.address();
  console.log(JSON.stringify({ status: "listening", address }, null, 2));

  const shutdown = () => {
    server.close(() => {
      process.exit(0);
    });
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
