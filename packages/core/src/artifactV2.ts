import { brokerArtifact } from "./artifact.js";
import { prepareToolOnboarding } from "./toolProtocolV2.js";
import type { ArtifactV2Input, ArtifactV2Result, RuntimeContext, ToolRequest } from "./types.js";

export function brokerArtifactV2(
  input: ArtifactV2Input,
  context: RuntimeContext
): ArtifactV2Result {
  const brokered = brokerArtifact(input, context);

  if (!input.followOnToolRequest) {
    return {
      ...brokered
    };
  }

  const followOnToolRequest: ToolRequest = {
    ...input.followOnToolRequest,
    sourceArtifactId: input.followOnToolRequest.sourceArtifactId ?? brokered.artifact.artifactId,
    sourceObservationId: input.followOnToolRequest.sourceObservationId ?? input.sourceObservationId,
    originatingSurface: input.followOnToolRequest.originatingSurface ?? "artifact",
    trustSignals: {
      ...input.followOnToolRequest.trustSignals,
      sourceOrigin:
        input.followOnToolRequest.trustSignals?.sourceOrigin ?? brokered.artifact.sourceOrigin,
      frameOrigin:
        input.followOnToolRequest.trustSignals?.frameOrigin ??
        brokered.artifact.viewerOrigin ??
        brokered.artifact.sourceOrigin,
      taintClass:
        input.followOnToolRequest.trustSignals?.taintClass ?? brokered.artifact.derivedTaintClass,
      lineageChain:
        input.followOnToolRequest.trustSignals?.lineageChain ?? brokered.artifact.lineageChain
    }
  };

  const prepared = prepareToolOnboarding(followOnToolRequest, context);

  return {
    ...brokered,
    followOnToolVerdict: prepared.verdict,
    workflowBinding: prepared.workflowBinding
  };
}
