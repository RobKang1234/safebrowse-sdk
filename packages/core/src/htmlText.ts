import { parse as parseHtmlDocument } from "parse5";

import { normalizeText } from "./utils.js";

type HtmlNode = {
  nodeName?: string;
  tagName?: string;
  value?: string;
  data?: string;
  childNodes?: HtmlNode[];
};

const SKIP_TEXT_TAGS = new Set(["script", "style", "template"]);

function collectText(node: HtmlNode, parts: string[]): void {
  const nodeName = node.nodeName?.toLowerCase() ?? "";
  if (nodeName === "#comment") {
    return;
  }

  if (nodeName === "#text") {
    const text = normalizeText(node.value ?? node.data ?? "");
    if (text) {
      parts.push(text);
    }
    return;
  }

  const tagName = node.tagName?.toLowerCase();
  if (tagName && SKIP_TEXT_TAGS.has(tagName)) {
    return;
  }

  for (const child of node.childNodes ?? []) {
    collectText(child, parts);
  }
}

export function extractTextFromHtml(html: string): string {
  if (!html) {
    return "";
  }

  const document = parseHtmlDocument(html) as unknown as HtmlNode;
  const parts: string[] = [];
  collectText(document, parts);
  return normalizeText(parts.join(" "));
}
