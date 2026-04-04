import { describe, expect, it } from "vitest";

import { extractTextFromHtml } from "../src/htmlText.js";

describe("extractTextFromHtml", () => {
  it("drops script and style content even when closing tags are malformed", () => {
    expect(
      extractTextFromHtml(
        `<main>Visible text</main><script>ignore("x")</script ><style>.x { color: red; }</style ><p>Still visible</p>`
      )
    ).toBe("Visible text Still visible");
  });

  it("drops comments and normalizes whitespace", () => {
    expect(
      extractTextFromHtml(`<div>Alpha</div><!-- hidden --><section>\n  Beta\tGamma  </section>`)
    ).toBe("Alpha Beta Gamma");
  });
});
