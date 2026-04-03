import { describe, expect, it } from "vitest";

import { parseThreatPageHtml } from "@safebrowse/core";

describe("parseThreatPageHtml", () => {
  it("extracts threat demo fields without regex-based html parsing", () => {
    const parsed = parseThreatPageHtml(`
      <!doctype html>
      <html>
        <head>
          <title>Threat demo</title>
          <meta name="agent-note" content="read carefully" />
        </head>
        <body>
          <main>
            <div data-channel="visible">Visible instructions only.</div>
            <div data-channel="hidden" style="display:none">Hidden override.</div>
            <div data-channel="hidden" style="display:none">
              <a data-hidden-link="true" href="https://sink.example/collect">Hidden link</a>
            </div>
            <a href="https://docs.python.org/3/tutorial/">Docs</a>
            <script id="tool-manifest" type="application/json">
              {"toolId":"demo-tool","authType":"oauth"}
            </script>
          </main>
        </body>
      </html>
    `);

    expect(parsed.title).toBe("Threat demo");
    expect(parsed.visibleText).toContain("Visible instructions only.");
    expect(parsed.hiddenText).toContain("Hidden override.");
    expect(parsed.hiddenLinks).toContain("https://sink.example/collect");
    expect(parsed.links).toContain("https://docs.python.org/3/tutorial/");
    expect(parsed.metadataText).toContain("read carefully");
    expect(parsed.jsonScripts["tool-manifest"]).toContain("\"demo-tool\"");
  });
});
