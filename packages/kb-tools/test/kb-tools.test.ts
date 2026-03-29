import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  buildKnowledgeBundle,
  loadKnowledgeBaseContext,
  loadPolicyPackFromPaths,
  verifyKnowledgeBundle
} from "@safebrowse/kb-tools";

describe("kb tools", () => {
  it("loads the multi-pack knowledge base from disk", async () => {
    const kb = await loadKnowledgeBaseContext(resolve(process.cwd(), "knowledge_base"));

    expect(kb.promptInjectionPatterns.length).toBeGreaterThan(100);
    expect(kb.actionIntegrityPatterns.length).toBeGreaterThan(10);
    expect(kb.artifactSurfacePatterns.length).toBeGreaterThan(10);
  });

  it("loads layered policy packs from yaml files", async () => {
    const pack = await loadPolicyPackFromPaths({
      base: resolve(process.cwd(), "policies/base/research.yaml"),
      tenant: resolve(process.cwd(), "policies/tenant/default.yaml"),
      project: resolve(process.cwd(), "policies/project/default.yaml"),
      emergency: resolve(process.cwd(), "policies/emergency/default.yaml")
    });

    expect(pack.layers).toHaveLength(4);
    expect(pack.profile).toBe("research");
  });

  it("builds and verifies a signed knowledge bundle", async () => {
    const workDir = await mkdtemp(join(tmpdir(), "safebrowse-kb-"));
    const bundle = await buildKnowledgeBundle({
      kbDir: resolve(process.cwd(), "knowledge_base"),
      indexFile: resolve(process.cwd(), "knowledge_base/safebrowse_vf_knowledge_base_index.json"),
      outputZip: join(workDir, "safebrowse_vf_knowledge_bases.zip"),
      outputZipSig: join(workDir, "safebrowse_vf_knowledge_bases.zip.sig"),
      outputIndexSig: join(workDir, "safebrowse_vf_knowledge_base_index.json.sig"),
      publicKeyOut: join(workDir, "safebrowse_vf_ed25519_public.pem"),
      privateKeyOut: join(workDir, "private", "safebrowse_vf_ed25519_private.pem"),
      generateDevKey: true
    });

    const verified = await verifyKnowledgeBundle({
      indexFile: resolve(process.cwd(), "knowledge_base/safebrowse_vf_knowledge_base_index.json"),
      outputZip: bundle.outputZip,
      outputZipSig: bundle.outputZipSig!,
      outputIndexSig: bundle.outputIndexSig!,
      publicKeyPath: join(workDir, "safebrowse_vf_ed25519_public.pem")
    });

    expect(verified).toBe(true);
  });
});
