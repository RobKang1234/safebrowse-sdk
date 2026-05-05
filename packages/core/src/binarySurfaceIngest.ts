import { basename, dirname, posix as pathPosix } from "node:path";

import { XMLParser } from "fast-xml-parser";
import { strFromU8, unzipSync } from "fflate";
import * as parse5 from "parse5";

import type {
  AttachmentDescriptor,
  DocxSurfaceCapture,
  EmailSurfaceCapture,
  ExtractionAttestation,
  PptxSurfaceCapture,
  SurfaceCapture,
  SurfaceLinkCapture,
  XlsxSurfaceCapture
} from "./types.js";
import { sha256Hex, uniq } from "./utils.js";

type XmlNode = Record<string, unknown>;
type Parse5Node = parse5.DefaultTreeAdapterMap["node"];
type Parse5Element = parse5.DefaultTreeAdapterMap["element"];

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  processEntities: false,
  trimValues: false
});

function arrayify<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function asRecord(value: unknown): XmlNode | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as XmlNode)
    : undefined;
}

function normalizedText(value: unknown): string {
  return typeof value === "string"
    ? value.replace(/\s+/g, " ").trim()
    : typeof value === "number"
      ? String(value)
      : "";
}

function decodeBase64(content: string): Uint8Array {
  return Uint8Array.from(Buffer.from(content, "base64"));
}

function bytesToText(bytes: Uint8Array): string {
  return strFromU8(bytes);
}

function decodeQuotedPrintable(value: string): string {
  return value
    .replace(/=\r?\n/g, "")
    .replace(/=([0-9A-Fa-f]{2})/g, (_match, group: string) =>
      String.fromCharCode(Number.parseInt(group, 16))
    );
}

function decodeMimeBody(value: string, transferEncoding: string | undefined): Uint8Array {
  const normalizedEncoding = (transferEncoding ?? "").trim().toLowerCase();
  if (normalizedEncoding === "base64") {
    return Uint8Array.from(Buffer.from(value.replace(/\s+/g, ""), "base64"));
  }
  if (normalizedEncoding === "quoted-printable") {
    return Uint8Array.from(Buffer.from(decodeQuotedPrintable(value), "utf8"));
  }
  return Uint8Array.from(Buffer.from(value, "utf8"));
}

function splitHeaderAndBody(raw: string): { headersText: string; bodyText: string } {
  const marker = raw.search(/\r?\n\r?\n/);
  if (marker === -1) {
    return {
      headersText: raw,
      bodyText: ""
    };
  }
  const separatorLength = raw.slice(marker).startsWith("\r\n\r\n") ? 4 : 2;
  return {
    headersText: raw.slice(0, marker),
    bodyText: raw.slice(marker + separatorLength)
  };
}

function parseHeaderMap(headersText: string): Array<{ key: string; originalKey: string; value: string }> {
  const lines = headersText.replace(/\r\n/g, "\n").split("\n");
  const merged: string[] = [];
  for (const line of lines) {
    if (/^\s/.test(line) && merged.length > 0) {
      merged[merged.length - 1] += ` ${line.trim()}`;
      continue;
    }
    merged.push(line);
  }

  return merged
    .map((line) => {
      const separatorIndex = line.indexOf(":");
      if (separatorIndex === -1) {
        return undefined;
      }
      const originalKey = line.slice(0, separatorIndex).trim();
      return {
        key: originalKey.toLowerCase(),
        originalKey,
        value: line.slice(separatorIndex + 1).trim()
      };
    })
    .filter((entry): entry is { key: string; originalKey: string; value: string } => Boolean(entry));
}

function headerValue(
  headers: Array<{ key: string; originalKey: string; value: string }>,
  key: string
): string | undefined {
  return headers.find((entry) => entry.key === key.toLowerCase())?.value;
}

function parseMimeParameters(value: string | undefined): { mimeType: string; params: Record<string, string> } {
  if (!value) {
    return {
      mimeType: "text/plain",
      params: {}
    };
  }

  const segments = value.split(";").map((segment) => segment.trim()).filter(Boolean);
  const mimeType = (segments.shift() ?? "text/plain").toLowerCase();
  const params: Record<string, string> = {};
  for (const segment of segments) {
    const separatorIndex = segment.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }
    const key = segment.slice(0, separatorIndex).trim().toLowerCase();
    const rawValue = segment.slice(separatorIndex + 1).trim();
    params[key] = rawValue.replace(/^"|"$/g, "");
  }

  return {
    mimeType,
    params
  };
}

function splitMultipart(bodyText: string, boundary: string): string[] {
  const marker = `--${boundary}`;
  return bodyText
    .split(marker)
    .slice(1)
    .map((part) => part.replace(/^\r?\n/, "").replace(/\r?\n--$/, "").trim())
    .filter(Boolean);
}

function extractEmailAddresses(value: string | undefined): string[] {
  if (!value) {
    return [];
  }
  return uniq(
    value
      .split(",")
      .map((entry) => entry.trim())
      .map((entry) => {
        const match = entry.match(/<([^>]+)>/);
        return (match?.[1] ?? entry).trim().toLowerCase();
      })
      .filter((entry) => entry.includes("@"))
  );
}

function isExternalUrl(value: string | undefined): value is string {
  if (!value) {
    return false;
  }
  return /^https?:\/\//i.test(value.trim());
}

function walkHtmlNodes(node: Parse5Node, visitor: (element: Parse5Element) => void): void {
  if (node.nodeName !== "#text" && "tagName" in node) {
    visitor(node as Parse5Element);
  }
  if ("childNodes" in node && Array.isArray(node.childNodes)) {
    for (const child of node.childNodes) {
      walkHtmlNodes(child, visitor);
    }
  }
}

function extractTextFromElement(node: Parse5Node): string {
  const fragments: string[] = [];
  const walk = (current: Parse5Node) => {
    if (current.nodeName === "#text" && "value" in current) {
      const text = normalizedText(current.value);
      if (text) {
        fragments.push(text);
      }
    }
    if ("childNodes" in current && Array.isArray(current.childNodes)) {
      for (const child of current.childNodes) {
        walk(child);
      }
    }
  };
  walk(node);
  return fragments.join(" ").trim();
}

function collectHtmlSignals(html: string): {
  remoteContent: string[];
  links: SurfaceLinkCapture[];
  quotedThreadText: string[];
} {
  const document = parse5.parse(html);
  const remoteContent: string[] = [];
  const links: SurfaceLinkCapture[] = [];
  const quotedThreadText: string[] = [];

  walkHtmlNodes(document, (element) => {
    if (element.tagName === "img" || element.tagName === "source" || element.tagName === "iframe") {
      const src = element.attrs.find((attr) => attr.name === "src")?.value;
      if (isExternalUrl(src)) {
        remoteContent.push(src);
      }
    }
    if (element.tagName === "a") {
      const href = element.attrs.find((attr) => attr.name === "href")?.value;
      if (isExternalUrl(href)) {
        links.push({
          href
        });
      }
    }
    if (element.tagName === "blockquote") {
      const excerpt = extractTextFromElement(element);
      if (excerpt) {
        quotedThreadText.push(excerpt);
      }
    }
  });

  return {
    remoteContent: uniq(remoteContent),
    links: uniq(links.map((entry) => JSON.stringify(entry))).map((entry) => JSON.parse(entry) as SurfaceLinkCapture),
    quotedThreadText: uniq(quotedThreadText)
  };
}

interface MimePart {
  headers: Array<{ key: string; originalKey: string; value: string }>;
  mimeType: string;
  disposition?: string;
  filename?: string;
  bodyBytes: Uint8Array;
  parts: MimePart[];
}

function parseMimeEntity(raw: string): MimePart {
  const { headersText, bodyText } = splitHeaderAndBody(raw);
  const headers = parseHeaderMap(headersText);
  const contentType = parseMimeParameters(headerValue(headers, "content-type"));
  const contentDisposition = parseMimeParameters(headerValue(headers, "content-disposition"));
  const boundary = contentType.params.boundary;
  if (boundary && contentType.mimeType.startsWith("multipart/")) {
    return {
      headers,
      mimeType: contentType.mimeType,
      disposition: contentDisposition.mimeType,
      filename: contentDisposition.params.filename ?? contentType.params.name,
      bodyBytes: new Uint8Array(),
      parts: splitMultipart(bodyText, boundary).map((part) => parseMimeEntity(part))
    };
  }

  return {
    headers,
    mimeType: contentType.mimeType,
    disposition: contentDisposition.mimeType,
    filename: contentDisposition.params.filename ?? contentType.params.name,
    bodyBytes: decodeMimeBody(bodyText, headerValue(headers, "content-transfer-encoding")),
    parts: []
  };
}

function flattenMimeParts(part: MimePart): MimePart[] {
  return [part, ...part.parts.flatMap((child) => flattenMimeParts(child))];
}

function buildBinaryAttachmentDescriptor(
  filename: string,
  mimeType: string,
  bytes: Uint8Array
): AttachmentDescriptor {
  const digest = sha256Hex(Buffer.from(bytes));
  return {
    attachmentId: digest.slice(0, 16),
    filename,
    mimeType,
    sha256: digest,
    sizeBytes: bytes.byteLength
  };
}

function rawEmailAttestation(inputDigest: string): ExtractionAttestation {
  return {
    extractorId: "safebrowse-mime-ingest",
    extractorVersion: "1.0.0",
    parserDigest: "safebrowse-mime-ingest",
    networkPolicy: "deny",
    maxRecursionDepth: 4,
    maxExpandedBytes: 10_000_000,
    extractedAt: new Date().toISOString(),
    inputDigest
  };
}

function materializeEmailCapture(capture: EmailSurfaceCapture): EmailSurfaceCapture {
  if (!capture.rawMimeBase64) {
    return capture;
  }

  const rawBytes = decodeBase64(capture.rawMimeBase64);
  const rawText = bytesToText(rawBytes);
  const root = parseMimeEntity(rawText);
  const allParts = flattenMimeParts(root);
  const rootHeaders = root.headers;
  const textBodies = allParts
    .filter((part) => part.mimeType === "text/plain" && !part.disposition?.startsWith("attachment"))
    .map((part) => bytesToText(part.bodyBytes))
    .filter(Boolean);
  const htmlBodies = allParts
    .filter((part) => part.mimeType === "text/html" && !part.disposition?.startsWith("attachment"))
    .map((part) => bytesToText(part.bodyBytes))
    .filter(Boolean);
  const attachments = allParts
    .filter((part) => part.filename && part.bodyBytes.byteLength > 0)
    .map((part) =>
      buildBinaryAttachmentDescriptor(part.filename ?? "attachment.bin", part.mimeType, part.bodyBytes)
    );
  const quotedThreadText = uniq(
    textBodies
      .flatMap((body) =>
        body
          .replace(/\r\n/g, "\n")
          .split("\n")
          .filter((line) => line.trim().startsWith(">"))
          .map((line) => line.replace(/^>\s?/, "").trim())
      )
      .filter(Boolean)
  );
  const htmlSignals = htmlBodies.reduce(
    (accumulator, body) => {
      const next = collectHtmlSignals(body);
      accumulator.remoteContent.push(...next.remoteContent);
      accumulator.links.push(...next.links);
      accumulator.quotedThreadText.push(...next.quotedThreadText);
      return accumulator;
    },
    {
      remoteContent: [] as string[],
      links: [] as SurfaceLinkCapture[],
      quotedThreadText: [] as string[]
    }
  );

  return {
    ...capture,
    parserId: "safebrowse-mime-ingest",
    parserVersion: "1.0.0",
    extractorId: "safebrowse-mime-ingest",
    extractorVersion: "1.0.0",
    sourceMode: capture.sourceMode ?? "pipeline_derived",
    sourceDigest: sha256Hex(Buffer.from(rawBytes)),
    subject: capture.subject ?? headerValue(rootHeaders, "subject"),
    from: capture.from ?? extractEmailAddresses(headerValue(rootHeaders, "from"))[0],
    to: capture.to ?? extractEmailAddresses(headerValue(rootHeaders, "to")),
    cc: capture.cc ?? extractEmailAddresses(headerValue(rootHeaders, "cc")),
    bcc: capture.bcc ?? extractEmailAddresses(headerValue(rootHeaders, "bcc")),
    bodyText: capture.bodyText ?? textBodies.join("\n\n").trim(),
    bodyHtml: capture.bodyHtml ?? htmlBodies.join("\n"),
    headers:
      capture.headers ??
      rootHeaders.map((entry) => `${entry.originalKey}: ${entry.value}`),
    authResults:
      capture.authResults ??
      rootHeaders
        .filter((entry) => entry.key === "authentication-results")
        .map((entry) => entry.value),
    quotedThreadText: uniq([...(capture.quotedThreadText ?? []), ...quotedThreadText, ...htmlSignals.quotedThreadText]),
    remoteContent: uniq([...(capture.remoteContent ?? []), ...htmlSignals.remoteContent]),
    links:
      capture.links && capture.links.length > 0
        ? capture.links
        : htmlSignals.links,
    attachments: capture.attachments?.length ? capture.attachments : attachments,
    extractionAttestation: capture.extractionAttestation ?? rawEmailAttestation(sha256Hex(Buffer.from(rawBytes)))
  };
}

function parseXmlEntry(entries: Record<string, Uint8Array>, entryName: string): XmlNode | undefined {
  const bytes = entries[entryName];
  if (!bytes) {
    return undefined;
  }
  return asRecord(xmlParser.parse(bytesToText(bytes)));
}

function walkXml(
  value: unknown,
  visitor: (node: XmlNode, path: string[]) => void,
  path: string[] = []
): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      walkXml(item, visitor, path);
    }
    return;
  }
  const record = asRecord(value);
  if (!record) {
    return;
  }
  visitor(record, path);
  for (const [key, child] of Object.entries(record)) {
    if (key.startsWith("@_") || key === "#text") {
      continue;
    }
    walkXml(child, visitor, [...path, key]);
  }
}

function collectTagTexts(xml: XmlNode | undefined, tagNames: string[]): string[] {
  if (!xml) {
    return [];
  }
  const values: string[] = [];
  walkXml(xml, (node) => {
    for (const [key, child] of Object.entries(node)) {
      if (!tagNames.includes(key)) {
        continue;
      }
      const text =
        typeof child === "string"
          ? normalizedText(child)
          : asRecord(child)
            ? normalizedText(asRecord(child)?.["#text"])
            : "";
      if (text) {
        values.push(text);
      }
    }
  });
  return uniq(values);
}

function relationshipEntries(xml: XmlNode | undefined): Array<{
  id?: string;
  target?: string;
  targetMode?: string;
  type?: string;
}> {
  if (!xml) {
    return [];
  }
  const root = asRecord(xml.Relationships) ?? xml;
  return arrayify(asRecord(root)?.Relationship).flatMap((value) =>
    arrayify(value).map((entry) => {
      const record = asRecord(entry) ?? {};
      return {
        id: normalizedText(record["@_Id"]),
        target: normalizedText(record["@_Target"]),
        targetMode: normalizedText(record["@_TargetMode"]),
        type: normalizedText(record["@_Type"])
      };
    })
  );
}

function resolveRelationshipTarget(baseEntry: string, target: string | undefined): string | undefined {
  if (!target) {
    return undefined;
  }
  if (/^[a-z]+:\/\//i.test(target)) {
    return target;
  }
  return pathPosix.normalize(pathPosix.join(dirname(baseEntry), target));
}

function collectRelationshipsByType(
  entries: Record<string, Uint8Array>,
  relEntry: string
): Array<{ type?: string; target?: string; targetMode?: string; id?: string }> {
  return relationshipEntries(parseXmlEntry(entries, relEntry)).map((entry) => ({
    ...entry,
    target: resolveRelationshipTarget(relEntry.replace("/_rels/", "/").replace(".rels", ""), entry.target)
  }));
}

function collectZipAttachments(
  entries: Record<string, Uint8Array>,
  prefix: string
): AttachmentDescriptor[] {
  return Object.entries(entries)
    .filter(([name]) => name.startsWith(prefix))
    .map(([name, bytes]) => buildBinaryAttachmentDescriptor(basename(name), "application/octet-stream", bytes));
}

function officeAttestation(kind: "docx" | "xlsx" | "pptx", inputDigest: string): ExtractionAttestation {
  return {
    extractorId: `safebrowse-${kind}-ingest`,
    extractorVersion: "1.0.0",
    parserDigest: `safebrowse-${kind}-ingest`,
    networkPolicy: "deny",
    maxRecursionDepth: 6,
    maxExpandedBytes: 25_000_000,
    extractedAt: new Date().toISOString(),
    inputDigest
  };
}

function collectWorkbookSheetMap(entries: Record<string, Uint8Array>): Array<{
  name: string;
  path?: string;
  hidden: boolean;
}> {
  const workbook = parseXmlEntry(entries, "xl/workbook.xml");
  const rels = relationshipEntries(parseXmlEntry(entries, "xl/_rels/workbook.xml.rels"));
  const relMap = new Map(rels.map((entry) => [entry.id, resolveRelationshipTarget("xl/workbook.xml", entry.target)]));
  const sheets = arrayify(asRecord(asRecord(workbook?.workbook)?.sheets)?.sheet);
  return sheets.map((entry) => {
    const record = asRecord(entry) ?? {};
    return {
      name: normalizedText(record["@_name"]),
      path: relMap.get(normalizedText(record["@_r:id"])),
      hidden: ["hidden", "veryHidden"].includes(normalizedText(record["@_state"]))
    };
  });
}

function collectWorksheetStrings(
  xml: XmlNode | undefined,
  sharedStrings: string[]
): { values: string[]; formulas: string[] } {
  const values: string[] = [];
  const formulas: string[] = [];
  if (!xml) {
    return { values, formulas };
  }

  walkXml(xml, (node, path) => {
    if (path[path.length - 1] !== "c") {
      return;
    }
    const cellType = normalizedText(node["@_t"]);
    const rawValue = normalizedText(node.v);
    const formula = normalizedText(node.f);
    if (formula) {
      formulas.push(formula);
    }
    if (!rawValue) {
      return;
    }
    if (cellType === "s") {
      const shared = sharedStrings[Number.parseInt(rawValue, 10)];
      if (shared) {
        values.push(shared);
      }
      return;
    }
    values.push(rawValue);
  });

  return {
    values: uniq(values.filter(Boolean)),
    formulas: uniq(formulas.filter(Boolean))
  };
}

function materializeDocxCapture(capture: DocxSurfaceCapture): DocxSurfaceCapture {
  if (!capture.contentBase64) {
    return capture;
  }
  const rawBytes = decodeBase64(capture.contentBase64);
  const entries = unzipSync(rawBytes);
  const digest = sha256Hex(Buffer.from(rawBytes));
  const documentXml = parseXmlEntry(entries, "word/document.xml");
  const commentsXml = parseXmlEntry(entries, "word/comments.xml");
  const footnotesXml = parseXmlEntry(entries, "word/footnotes.xml");
  const endnotesXml = parseXmlEntry(entries, "word/endnotes.xml");
  const metadataXml = parseXmlEntry(entries, "docProps/core.xml");
  const documentRels = collectRelationshipsByType(entries, "word/_rels/document.xml.rels");

  const visibleText: string[] = [];
  const hiddenText: string[] = [];
  const trackedChanges: string[] = [];

  walkXml(documentXml, (node, path) => {
    const currentKey = path[path.length - 1];
    if (currentKey !== "w:r" && currentKey !== "r") {
      return;
    }
    const texts = collectTagTexts(node, ["w:t", "t"]);
    if (!texts.length) {
      return;
    }
    const runText = texts.join(" ");
    const runProperties = asRecord(node["w:rPr"] ?? node.rPr);
    const hidden =
      Boolean(runProperties) &&
      ("w:vanish" in (runProperties ?? {}) || "vanish" in (runProperties ?? {}));
    const tracked = path.includes("w:ins") || path.includes("w:del") || path.includes("ins") || path.includes("del");
    if (tracked) {
      trackedChanges.push(runText);
      return;
    }
    if (hidden) {
      hiddenText.push(runText);
      return;
    }
    visibleText.push(runText);
  });

  const relMap = new Map(documentRels.map((entry) => [entry.id, entry.target]));
  const links: SurfaceLinkCapture[] = [];
  walkXml(documentXml, (node, path) => {
    const currentKey = path[path.length - 1];
    if (currentKey !== "w:hyperlink" && currentKey !== "hyperlink") {
      return;
    }
    const href = relMap.get(normalizedText(node["@_r:id"]));
    if (!isExternalUrl(href)) {
      return;
    }
    links.push({
      href,
      text: collectTagTexts(node, ["w:t", "t"]).join(" ")
    });
  });

  return {
    ...capture,
    parserId: "safebrowse-docx-ingest",
    parserVersion: "1.0.0",
    extractorId: "safebrowse-docx-ingest",
    extractorVersion: "1.0.0",
    sourceMode: capture.sourceMode ?? "pipeline_derived",
    sourceDigest: digest,
    visibleText: capture.visibleText ?? uniq(visibleText).join(" ").trim(),
    metadataText:
      capture.metadataText && capture.metadataText.length > 0
        ? capture.metadataText
        : collectTagTexts(metadataXml, ["dc:title", "dc:subject", "dc:creator", "cp:keywords"]),
    comments: capture.comments && capture.comments.length > 0 ? capture.comments : collectTagTexts(commentsXml, ["w:t", "t"]),
    notes:
      capture.notes && capture.notes.length > 0
        ? capture.notes
        : uniq([...collectTagTexts(footnotesXml, ["w:t", "t"]), ...collectTagTexts(endnotesXml, ["w:t", "t"])]),
    trackedChanges: capture.trackedChanges && capture.trackedChanges.length > 0 ? capture.trackedChanges : uniq(trackedChanges),
    hiddenText: capture.hiddenText && capture.hiddenText.length > 0 ? capture.hiddenText : uniq(hiddenText),
    externalRelationships:
      capture.externalRelationships && capture.externalRelationships.length > 0
        ? capture.externalRelationships
        : uniq(
            documentRels
              .filter((entry) => entry.targetMode?.toLowerCase() === "external" && entry.target)
              .map((entry) => entry.target ?? "")
              .filter(Boolean)
          ),
    embeddedObjects:
      capture.embeddedObjects && capture.embeddedObjects.length > 0
        ? capture.embeddedObjects
        : uniq(
            documentRels
              .filter(
                (entry) =>
                  (entry.type ?? "").toLowerCase().includes("oleobject") ||
                  (entry.type ?? "").toLowerCase().includes("package")
              )
              .map((entry) => entry.target ?? "")
              .filter(Boolean)
          ),
    links:
      capture.links && capture.links.length > 0
        ? capture.links
        : uniq(links.map((entry) => JSON.stringify(entry))).map((entry) => JSON.parse(entry) as SurfaceLinkCapture),
    attachments:
      capture.attachments && capture.attachments.length > 0
        ? capture.attachments
        : collectZipAttachments(entries, "word/embeddings/"),
    unsupportedSubtrees:
      capture.unsupportedSubtrees && capture.unsupportedSubtrees.length > 0
        ? capture.unsupportedSubtrees
        : uniq(Object.keys(entries).filter((name) => name.endsWith("vbaProject.bin") || name.startsWith("customXml/"))),
    extractionAttestation: capture.extractionAttestation ?? officeAttestation("docx", digest)
  };
}

function materializeXlsxCapture(capture: XlsxSurfaceCapture): XlsxSurfaceCapture {
  if (!capture.contentBase64) {
    return capture;
  }
  const rawBytes = decodeBase64(capture.contentBase64);
  const entries = unzipSync(rawBytes);
  const digest = sha256Hex(Buffer.from(rawBytes));
  const sharedStrings = collectTagTexts(parseXmlEntry(entries, "xl/sharedStrings.xml"), ["t"]);
  const metadataXml = parseXmlEntry(entries, "docProps/core.xml");
  const workbookRels = collectRelationshipsByType(entries, "xl/_rels/workbook.xml.rels");
  const sheets = collectWorkbookSheetMap(entries);
  const visibleValues: string[] = [];
  const hiddenText: string[] = [];
  const formulas: string[] = [];
  const links: SurfaceLinkCapture[] = [];

  for (const sheet of sheets) {
    if (!sheet.path) {
      continue;
    }
    const worksheetXml = parseXmlEntry(entries, sheet.path);
    const collected = collectWorksheetStrings(worksheetXml, sharedStrings);
    const targetValues = sheet.hidden ? hiddenText : visibleValues;
    targetValues.push(...collected.values.map((value) => (sheet.name ? `${sheet.name}: ${value}` : value)));
    formulas.push(...collected.formulas.map((value) => (sheet.name ? `${sheet.name}: ${value}` : value)));
    const sheetRelPath = pathPosix.join(dirname(sheet.path), "_rels", `${basename(sheet.path)}.rels`);
    const sheetRelationships = collectRelationshipsByType(entries, sheetRelPath);
    const hyperlinkMap = new Map(
      sheetRelationships
        .filter((entry) => (entry.type ?? "").toLowerCase().includes("hyperlink") && isExternalUrl(entry.target))
        .map((entry) => [entry.id, entry.target])
    );
    walkXml(worksheetXml, (node, path) => {
      if (path[path.length - 1] !== "hyperlink") {
        return;
      }
      const href = hyperlinkMap.get(normalizedText(node["@_r:id"]));
      if (!href) {
        return;
      }
      links.push({
        href,
        text: normalizedText(node["@_display"]) || href
      });
    });
  }

  return {
    ...capture,
    parserId: "safebrowse-xlsx-ingest",
    parserVersion: "1.0.0",
    extractorId: "safebrowse-xlsx-ingest",
    extractorVersion: "1.0.0",
    sourceMode: capture.sourceMode ?? "pipeline_derived",
    sourceDigest: digest,
    visibleText: capture.visibleText ?? uniq(visibleValues).join(" ").trim(),
    metadataText:
      capture.metadataText && capture.metadataText.length > 0
        ? capture.metadataText
        : collectTagTexts(metadataXml, ["dc:title", "dc:subject", "dc:creator", "cp:keywords"]),
    comments:
      capture.comments && capture.comments.length > 0
        ? capture.comments
        : uniq(
            Object.keys(entries)
              .filter((name) => /xl\/comments\d+\.xml$/i.test(name))
              .flatMap((name) => collectTagTexts(parseXmlEntry(entries, name), ["t"]))
          ),
    hiddenText: capture.hiddenText && capture.hiddenText.length > 0 ? capture.hiddenText : uniq(hiddenText),
    formulas: capture.formulas && capture.formulas.length > 0 ? capture.formulas : uniq(formulas),
    externalRelationships:
      capture.externalRelationships && capture.externalRelationships.length > 0
        ? capture.externalRelationships
        : uniq(
            workbookRels
              .filter((entry) => entry.targetMode?.toLowerCase() === "external" && entry.target)
              .map((entry) => entry.target ?? "")
              .concat(
                Object.keys(entries).filter((name) => name.startsWith("xl/externalLinks/") || name.endsWith("connections.xml"))
              )
              .filter(Boolean)
          ),
    embeddedObjects:
      capture.embeddedObjects && capture.embeddedObjects.length > 0
        ? capture.embeddedObjects
        : Object.keys(entries)
            .filter((name) => name.startsWith("xl/embeddings/"))
            .map((name) => basename(name)),
    links:
      capture.links && capture.links.length > 0
        ? capture.links
        : uniq(links.map((entry) => JSON.stringify(entry))).map((entry) => JSON.parse(entry) as SurfaceLinkCapture),
    attachments:
      capture.attachments && capture.attachments.length > 0
        ? capture.attachments
        : collectZipAttachments(entries, "xl/embeddings/"),
    unsupportedSubtrees:
      capture.unsupportedSubtrees && capture.unsupportedSubtrees.length > 0
        ? capture.unsupportedSubtrees
        : uniq(Object.keys(entries).filter((name) => name.endsWith("vbaProject.bin") || name.includes("/printerSettings/"))),
    extractionAttestation: capture.extractionAttestation ?? officeAttestation("xlsx", digest)
  };
}

function materializePptxCapture(capture: PptxSurfaceCapture): PptxSurfaceCapture {
  if (!capture.contentBase64) {
    return capture;
  }
  const rawBytes = decodeBase64(capture.contentBase64);
  const entries = unzipSync(rawBytes);
  const digest = sha256Hex(Buffer.from(rawBytes));
  const metadataXml = parseXmlEntry(entries, "docProps/core.xml");
  const slideEntryNames = Object.keys(entries).filter((name) => /^ppt\/slides\/slide\d+\.xml$/i.test(name));
  const noteEntryNames = Object.keys(entries).filter((name) => /^ppt\/notesSlides\/notesSlide\d+\.xml$/i.test(name));
  const visibleText = slideEntryNames.flatMap((name) => collectTagTexts(parseXmlEntry(entries, name), ["a:t", "t"]));
  const notes = noteEntryNames.flatMap((name) => collectTagTexts(parseXmlEntry(entries, name), ["a:t", "t"]));
  const comments = Object.keys(entries)
    .filter((name) => /^ppt\/comments\/comment\d+\.xml$/i.test(name))
    .flatMap((name) => collectTagTexts(parseXmlEntry(entries, name), ["p:text", "text", "a:t", "t"]));
  const links: SurfaceLinkCapture[] = [];
  const externalRelationships: string[] = [];

  for (const slideEntry of slideEntryNames) {
    const relPath = pathPosix.join(dirname(slideEntry), "_rels", `${basename(slideEntry)}.rels`);
    for (const relationship of collectRelationshipsByType(entries, relPath)) {
      if ((relationship.type ?? "").toLowerCase().includes("hyperlink") && isExternalUrl(relationship.target)) {
        links.push({
          href: relationship.target,
          text: relationship.target
        });
      }
      if (relationship.targetMode?.toLowerCase() === "external" && relationship.target) {
        externalRelationships.push(relationship.target);
      }
    }
  }

  return {
    ...capture,
    parserId: "safebrowse-pptx-ingest",
    parserVersion: "1.0.0",
    extractorId: "safebrowse-pptx-ingest",
    extractorVersion: "1.0.0",
    sourceMode: capture.sourceMode ?? "pipeline_derived",
    sourceDigest: digest,
    visibleText: capture.visibleText ?? uniq(visibleText).join(" ").trim(),
    metadataText:
      capture.metadataText && capture.metadataText.length > 0
        ? capture.metadataText
        : collectTagTexts(metadataXml, ["dc:title", "dc:subject", "dc:creator", "cp:keywords"]),
    comments: capture.comments && capture.comments.length > 0 ? capture.comments : uniq(comments),
    notes: capture.notes && capture.notes.length > 0 ? capture.notes : uniq(notes),
    hiddenText: capture.hiddenText && capture.hiddenText.length > 0 ? capture.hiddenText : [],
    externalRelationships:
      capture.externalRelationships && capture.externalRelationships.length > 0
        ? capture.externalRelationships
        : uniq(externalRelationships),
    embeddedObjects:
      capture.embeddedObjects && capture.embeddedObjects.length > 0
        ? capture.embeddedObjects
        : Object.keys(entries)
            .filter((name) => name.startsWith("ppt/embeddings/"))
            .map((name) => basename(name)),
    links:
      capture.links && capture.links.length > 0
        ? capture.links
        : uniq(links.map((entry) => JSON.stringify(entry))).map((entry) => JSON.parse(entry) as SurfaceLinkCapture),
    attachments:
      capture.attachments && capture.attachments.length > 0
        ? capture.attachments
        : collectZipAttachments(entries, "ppt/embeddings/"),
    unsupportedSubtrees:
      capture.unsupportedSubtrees && capture.unsupportedSubtrees.length > 0
        ? capture.unsupportedSubtrees
        : uniq(Object.keys(entries).filter((name) => name.endsWith("vbaProject.bin"))),
    extractionAttestation: capture.extractionAttestation ?? officeAttestation("pptx", digest)
  };
}

export function materializeBinarySurfaceCapture(capture: SurfaceCapture): SurfaceCapture {
  if (capture.surfaceType === "email_message") {
    return materializeEmailCapture(capture);
  }
  if (capture.surfaceType === "docx") {
    return materializeDocxCapture(capture);
  }
  if (capture.surfaceType === "xlsx") {
    return materializeXlsxCapture(capture);
  }
  if (capture.surfaceType === "pptx") {
    return materializePptxCapture(capture);
  }
  return capture;
}
