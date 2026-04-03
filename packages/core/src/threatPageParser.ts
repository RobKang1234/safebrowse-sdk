import { parse as parseHtmlDocument } from "parse5";

type HtmlAttr = {
  name: string;
  value: string;
};

type HtmlNode = {
  nodeName?: string;
  tagName?: string;
  value?: string;
  data?: string;
  attrs?: HtmlAttr[];
  childNodes?: HtmlNode[];
};

export interface ParsedThreatPageHtml {
  title: string;
  visibleText: string;
  hiddenText: string[];
  hiddenLinks: string[];
  metadataText: string[];
  links: string[];
  jsonScripts: Record<string, string>;
}

const SKIP_TEXT_TAGS = new Set(["script", "style", "template", "noscript"]);

function getAttr(node: HtmlNode, name: string): string | undefined {
  return node.attrs?.find((attr) => attr.name.toLowerCase() === name)?.value;
}

function isAsciiWhitespace(char: string): boolean {
  return (
    char === " " ||
    char === "\t" ||
    char === "\n" ||
    char === "\r" ||
    char === "\f" ||
    char === "\v"
  );
}

function normalizeText(value: string): string {
  let result = "";
  let previousWasWhitespace = false;

  for (const char of value) {
    if (isAsciiWhitespace(char)) {
      if (result && !previousWasWhitespace) {
        result += " ";
      }
      previousWasWhitespace = true;
    } else {
      result += char;
      previousWasWhitespace = false;
    }
  }

  return result.trim();
}

function stripAsciiWhitespace(value: string): string {
  let result = "";
  for (const char of value) {
    if (!isAsciiWhitespace(char)) {
      result += char;
    }
  }
  return result;
}

function styleContainsHiddenSignal(style: string | undefined): boolean {
  if (!style) {
    return false;
  }

  for (const declaration of style.toLowerCase().split(";")) {
    const separator = declaration.indexOf(":");
    if (separator === -1) {
      continue;
    }

    const property = declaration.slice(0, separator).trim();
    const value = stripAsciiWhitespace(declaration.slice(separator + 1));

    if ((property === "display" && value === "none") || (property === "visibility" && value === "hidden")) {
      return true;
    }
  }

  return false;
}

function elementHasHiddenSignal(node: HtmlNode): boolean {
  if (!node.tagName) {
    return false;
  }

  const hidden = getAttr(node, "hidden");
  const inert = getAttr(node, "inert");
  const ariaHidden = getAttr(node, "aria-hidden")?.toLowerCase();

  return (
    hidden !== undefined ||
    inert !== undefined ||
    ariaHidden === "true" ||
    styleContainsHiddenSignal(getAttr(node, "style"))
  );
}

function nodeText(node: HtmlNode): string {
  return normalizeText(node.value ?? node.data ?? "");
}

function textContent(node: HtmlNode): string {
  const nodeName = node.nodeName?.toLowerCase() ?? "";
  if (nodeName === "#text") {
    return nodeText(node);
  }
  if (nodeName === "#comment") {
    return "";
  }

  const tagName = node.tagName?.toLowerCase();
  if (tagName && SKIP_TEXT_TAGS.has(tagName)) {
    return "";
  }

  return normalizeText((node.childNodes ?? []).map((child) => textContent(child)).join(" "));
}

function rawTextContent(node: HtmlNode): string {
  const nodeName = node.nodeName?.toLowerCase() ?? "";
  if (nodeName === "#text") {
    return node.value ?? node.data ?? "";
  }
  if (nodeName === "#comment") {
    return "";
  }
  return (node.childNodes ?? []).map((child) => rawTextContent(child)).join("");
}

function uniqStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

export function parseThreatPageHtml(html: string): ParsedThreatPageHtml {
  const result: ParsedThreatPageHtml = {
    title: "Untitled",
    visibleText: "",
    hiddenText: [],
    hiddenLinks: [],
    metadataText: [],
    links: [],
    jsonScripts: {}
  };

  if (!html) {
    return result;
  }

  const visibleSegments: string[] = [];
  const document = parseHtmlDocument(html) as unknown as HtmlNode;

  function walk(node: HtmlNode, hiddenAncestor: boolean): void {
    const tagName = node.tagName?.toLowerCase();
    const nodeName = node.nodeName?.toLowerCase() ?? "";

    if (nodeName === "#text" || nodeName === "#comment") {
      return;
    }

    const hidden = hiddenAncestor || elementHasHiddenSignal(node);

    if (tagName === "title") {
      const title = textContent(node);
      if (title) {
        result.title = title;
      }
    } else if (tagName === "meta") {
      const metaName = getAttr(node, "name")?.toLowerCase();
      const metaContent = normalizeText(getAttr(node, "content") ?? "");
      if (metaName === "agent-note" && metaContent) {
        result.metadataText.push(metaContent);
      }
    } else if (tagName === "div") {
      const channel = getAttr(node, "data-channel")?.toLowerCase();
      if (channel === "visible") {
        const visibleText = textContent(node);
        if (visibleText) {
          visibleSegments.push(visibleText);
        }
      } else if (channel === "hidden") {
        const hiddenText = textContent(node);
        if (hiddenText) {
          result.hiddenText.push(hiddenText);
        }
      }
    } else if (tagName === "a") {
      const href = normalizeText(getAttr(node, "href") ?? "");
      if (href) {
        if (getAttr(node, "data-hidden-link")?.toLowerCase() === "true" || hidden) {
          result.hiddenLinks.push(href);
        } else {
          result.links.push(href);
        }
      }
    } else if (tagName === "script") {
      const type = getAttr(node, "type")?.toLowerCase();
      const id = getAttr(node, "id");
      if (type === "application/json" && id) {
        result.jsonScripts[id] = rawTextContent(node);
      }
    }

    for (const child of node.childNodes ?? []) {
      walk(child, hidden);
    }
  }

  walk(document, false);

  result.visibleText = normalizeText(visibleSegments.join(" "));
  result.hiddenText = uniqStrings(result.hiddenText);
  result.hiddenLinks = uniqStrings(result.hiddenLinks);
  result.metadataText = uniqStrings(result.metadataText);
  result.links = uniqStrings(result.links);

  return result;
}
