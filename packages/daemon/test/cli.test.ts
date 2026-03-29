import { describe, expect, it } from "vitest";

import { formatDaemonHelp, parseDaemonOptions } from "@safebrowse/daemon";

describe("safebrowse daemon cli", () => {
  it("parses explicit flags", () => {
    const parsed = parseDaemonOptions([
      "--host",
      "0.0.0.0",
      "--port",
      "9898",
      "--root-dir",
      "."
    ]);

    expect(parsed.host).toBe("0.0.0.0");
    expect(parsed.port).toBe(9898);
    expect(parsed.rootDir).toMatch(/[\\/]safebrowse-sdk$/);
  });

  it("reads matching environment variables", () => {
    const parsed = parseDaemonOptions([], {
      SAFEBROWSE_HOST: "127.0.0.2",
      SAFEBROWSE_PORT: "9001",
      SAFEBROWSE_ROOT_DIR: "."
    });

    expect(parsed.host).toBe("127.0.0.2");
    expect(parsed.port).toBe(9001);
    expect(parsed.rootDir).toMatch(/[\\/]safebrowse-sdk$/);
  });

  it("formats help text for the public bin", () => {
    expect(formatDaemonHelp()).toContain("safebrowse-daemon");
    expect(formatDaemonHelp()).toContain("SAFEBROWSE_HOST");
  });
});
