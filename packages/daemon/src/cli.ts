import { resolve } from "node:path";
import process from "node:process";

import { startSafeBrowseDaemon, type SafeBrowseDaemonOptions } from "./server.js";

export interface ParsedDaemonOptions extends SafeBrowseDaemonOptions {
  help?: boolean;
}

const HELP_TEXT = `SafeBrowse daemon

Usage:
  safebrowse-daemon [--host 127.0.0.1] [--port 8787] [--root-dir <path>] [--deployment-profile development|secure_v5|secure_v6]
                    [--approval-broker-mode signature_verification|external_service]
                    [--parser-isolation-mode scrubbed_process|node_permission_process]

Environment:
  SAFEBROWSE_HOST
  SAFEBROWSE_PORT
  SAFEBROWSE_ROOT_DIR
  SAFEBROWSE_DEPLOYMENT_PROFILE
  SAFEBROWSE_APPROVAL_BROKER_PUBLIC_KEY_PATH
  SAFEBROWSE_APPROVAL_BROKER_MODE
  SAFEBROWSE_PARSER_ISOLATION_MODE
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
  const envDeploymentProfile = env.SAFEBROWSE_DEPLOYMENT_PROFILE?.trim();
  const envApprovalBrokerPublicKeyPath = env.SAFEBROWSE_APPROVAL_BROKER_PUBLIC_KEY_PATH?.trim();
  const envApprovalBrokerMode = env.SAFEBROWSE_APPROVAL_BROKER_MODE?.trim();
  const envParserIsolationMode = env.SAFEBROWSE_PARSER_ISOLATION_MODE?.trim();

  if (envHost) {
    options.host = envHost;
  }
  if (envPort) {
    options.port = parsePort(envPort);
  }
  if (envRootDir) {
    options.rootDir = resolve(envRootDir);
  }
  if (
    envDeploymentProfile === "development" ||
    envDeploymentProfile === "secure_v5" ||
    envDeploymentProfile === "secure_v6"
  ) {
    options.deploymentProfile = envDeploymentProfile;
  }
  if (envApprovalBrokerPublicKeyPath) {
    options.approvalBrokerPublicKeyPath = resolve(envApprovalBrokerPublicKeyPath);
  }
  if (envApprovalBrokerMode === "signature_verification" || envApprovalBrokerMode === "external_service") {
    options.approvalBrokerMode = envApprovalBrokerMode;
  }
  if (
    envParserIsolationMode === "scrubbed_process" ||
    envParserIsolationMode === "node_permission_process"
  ) {
    options.parserIsolationMode = envParserIsolationMode;
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

    if (arg === "--deployment-profile") {
      const value = queue.shift();
      if (!value || !["development", "secure_v5", "secure_v6"].includes(value)) {
        throw new Error("Invalid value for --deployment-profile");
      }
      options.deploymentProfile = value as "development" | "secure_v5" | "secure_v6";
      continue;
    }

    if (arg === "--approval-broker-public-key-path") {
      const value = queue.shift();
      if (!value) {
        throw new Error("Missing value for --approval-broker-public-key-path");
      }
      options.approvalBrokerPublicKeyPath = resolve(value);
      continue;
    }

    if (arg === "--approval-broker-mode") {
      const value = queue.shift();
      if (!value || !["signature_verification", "external_service"].includes(value)) {
        throw new Error("Invalid value for --approval-broker-mode");
      }
      options.approvalBrokerMode = value as "signature_verification" | "external_service";
      continue;
    }

    if (arg === "--parser-isolation-mode") {
      const value = queue.shift();
      if (!value || !["scrubbed_process", "node_permission_process"].includes(value)) {
        throw new Error("Invalid value for --parser-isolation-mode");
      }
      options.parserIsolationMode = value as "scrubbed_process" | "node_permission_process";
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
