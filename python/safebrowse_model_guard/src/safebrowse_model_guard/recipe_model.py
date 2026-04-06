from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .features import LABEL_TO_ID, RECIPE_CATEGORICAL_FIELDS, RECIPE_NUMERIC_FIELDS, RECIPE_REASON_LABELS


def _require_model_dependencies() -> dict[str, Any]:
    try:
        import torch
        import torch.nn.functional as F
        from torch import nn
        from transformers import AutoModel, AutoTokenizer
        from peft import LoraConfig, PeftModel, TaskType, get_peft_model
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "Recipe expert training requires torch, transformers, and peft. "
            "Install the optional train dependencies before running ModernBERT training."
        ) from exc
    return {
        "torch": torch,
        "F": F,
        "nn": nn,
        "AutoModel": AutoModel,
        "AutoTokenizer": AutoTokenizer,
        "LoraConfig": LoraConfig,
        "PeftModel": PeftModel,
        "TaskType": TaskType,
        "get_peft_model": get_peft_model,
    }


@dataclass
class RecipeExpertConfig:
    backbone: str
    top_k_chunks: int
    max_length: int
    categorical_vocab_sizes: dict[str, int]
    categorical_embedding_dim: int = 16
    aggregator_hidden_dim: int = 512
    fusion_hidden_dims: list[int] = field(default_factory=lambda: [256, 128])
    reason_labels: list[str] = field(default_factory=lambda: list(RECIPE_REASON_LABELS))
    peft_method: str = "lora"
    use_dora: bool = False
    lora_rank: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    feature_schema_version: str = "recipe_v1"
    aggregation: str = "transformer_encoder_summary_token"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["categorical_fields"] = list(RECIPE_CATEGORICAL_FIELDS)
        payload["numeric_fields"] = list(RECIPE_NUMERIC_FIELDS)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RecipeExpertConfig":
        return cls(
            backbone=str(payload["backbone"]),
            top_k_chunks=int(payload["top_k_chunks"]),
            max_length=int(payload["max_length"]),
            categorical_vocab_sizes={str(key): int(value) for key, value in payload["categorical_vocab_sizes"].items()},
            categorical_embedding_dim=int(payload.get("categorical_embedding_dim", 16)),
            aggregator_hidden_dim=int(payload.get("aggregator_hidden_dim", 512)),
            fusion_hidden_dims=[int(value) for value in payload.get("fusion_hidden_dims", [256, 128])],
            reason_labels=[str(value) for value in payload.get("reason_labels", list(RECIPE_REASON_LABELS))],
            peft_method=str(payload.get("peft_method", "lora")),
            use_dora=bool(payload.get("use_dora", False)),
            lora_rank=int(payload.get("lora_rank", 16)),
            lora_alpha=int(payload.get("lora_alpha", 32)),
            lora_dropout=float(payload.get("lora_dropout", 0.05)),
            feature_schema_version=str(payload.get("feature_schema_version", "recipe_v1")),
            aggregation=str(payload.get("aggregation", "transformer_encoder_summary_token")),
        )


def _base_module() -> type[Any]:
    return _require_model_dependencies()["nn"].Module


class HierarchicalActionGuardModel(_base_module()):  # pragma: no cover - exercised through torch runtime
    def __init__(self, encoder: Any, config: RecipeExpertConfig):
        deps = _require_model_dependencies()
        nn = deps["nn"]
        super().__init__()
        self.encoder = encoder
        self.recipe_config = config
        hidden_size = int(getattr(self.encoder.config, "hidden_size", 768))
        aggregator_dim = int(config.aggregator_hidden_dim)
        self.chunk_projection = nn.Linear(hidden_size, aggregator_dim)
        self.summary_token = nn.Parameter(deps["torch"].zeros(1, 1, aggregator_dim))
        nn.init.normal_(self.summary_token, std=0.02)
        self.position_embeddings = nn.Parameter(
            deps["torch"].zeros(1, config.top_k_chunks + 1, aggregator_dim)
        )
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=aggregator_dim,
            nhead=8,
            dim_feedforward=aggregator_dim * 2,
            dropout=0.1,
            activation="gelu",
            batch_first=True,
        )
        self.aggregator = nn.TransformerEncoder(encoder_layer, num_layers=2)
        self.categorical_embeddings = nn.ModuleDict(
            {
                field: nn.Embedding(max(2, config.categorical_vocab_sizes.get(field, 2)), config.categorical_embedding_dim)
                for field in RECIPE_CATEGORICAL_FIELDS
            }
        )
        cat_dim = len(RECIPE_CATEGORICAL_FIELDS) * config.categorical_embedding_dim
        self.numeric_norm = nn.LayerNorm(len(RECIPE_NUMERIC_FIELDS))
        self.metadata_fusion = nn.Sequential(
            nn.Linear(cat_dim + len(RECIPE_NUMERIC_FIELDS), config.fusion_hidden_dims[0]),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(config.fusion_hidden_dims[0], config.fusion_hidden_dims[1]),
            nn.GELU(),
            nn.Dropout(0.1),
        )
        shared_dim = aggregator_dim + config.fusion_hidden_dims[-1]
        self.shared = nn.Sequential(
            nn.Linear(shared_dim, aggregator_dim),
            nn.GELU(),
            nn.Dropout(0.1),
        )
        self.decision_head = nn.Linear(aggregator_dim, len(LABEL_TO_ID))
        self.binary_threat_head = nn.Linear(aggregator_dim, 1)
        self.reason_head = nn.Linear(aggregator_dim, len(config.reason_labels))
        self.embedding_head = nn.Linear(aggregator_dim, 128)
        self.register_buffer(
            "decision_loss_weights",
            deps["torch"].tensor([1.0, 1.3, 1.6, 2.0], dtype=deps["torch"].float32),
            persistent=False,
        )

    def encode_chunks(self, input_ids: Any, attention_mask: Any) -> tuple[Any, Any]:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask, return_dict=True)
        hidden = outputs.last_hidden_state[:, 0, :]
        projected = self.chunk_projection(hidden)
        return projected, hidden

    def aggregate_document(self, chunk_embeddings: Any, metadata_categorical: Any, metadata_numeric: Any) -> tuple[Any, Any]:
        deps = _require_model_dependencies()
        batch_size = chunk_embeddings.shape[0]
        summary = self.summary_token.expand(batch_size, -1, -1)
        sequence = deps["torch"].cat([summary, chunk_embeddings], dim=1)
        sequence = sequence + self.position_embeddings[:, : sequence.shape[1], :]
        aggregated = self.aggregator(sequence)[:, 0, :]
        categorical_vectors = []
        for index, field in enumerate(RECIPE_CATEGORICAL_FIELDS):
            categorical_vectors.append(self.categorical_embeddings[field](metadata_categorical[:, index]))
        categorical_fused = deps["torch"].cat(categorical_vectors, dim=-1)
        numeric_fused = self.numeric_norm(metadata_numeric)
        metadata_fused = self.metadata_fusion(
            deps["torch"].cat([categorical_fused, numeric_fused], dim=-1)
        )
        shared = self.shared(deps["torch"].cat([aggregated, metadata_fused], dim=-1))
        embedding = deps["F"].normalize(self.embedding_head(shared), dim=-1)
        return shared, embedding

    def contrastive_loss(self, embeddings: Any, labels: Any) -> Any:
        deps = _require_model_dependencies()
        if embeddings.shape[0] < 2:
            return embeddings.new_tensor(0.0)
        similarity = embeddings @ embeddings.transpose(0, 1)
        similarity = similarity / 0.1
        loss_terms = []
        for index in range(embeddings.shape[0]):
            positive_mask = labels == labels[index]
            positive_mask[index] = False
            if int(positive_mask.sum().item()) == 0:
                continue
            log_denominator = deps["torch"].logsumexp(similarity[index], dim=0)
            log_numerator = deps["torch"].logsumexp(similarity[index][positive_mask], dim=0)
            loss_terms.append(-(log_numerator - log_denominator))
        if not loss_terms:
            return embeddings.new_tensor(0.0)
        return deps["torch"].stack(loss_terms).mean()

    def forward(
        self,
        *,
        input_ids: Any,
        attention_mask: Any,
        metadata_categorical: Any,
        metadata_numeric: Any,
        labels: Any | None = None,
        threat_labels: Any | None = None,
        reason_labels: Any | None = None,
    ) -> dict[str, Any]:
        deps = _require_model_dependencies()
        batch_size = metadata_categorical.shape[0]
        flat_embeddings, base_hidden = self.encode_chunks(input_ids=input_ids, attention_mask=attention_mask)
        chunk_embeddings = flat_embeddings.view(batch_size, self.recipe_config.top_k_chunks, -1)
        shared, pooled_embedding = self.aggregate_document(
            chunk_embeddings=chunk_embeddings,
            metadata_categorical=metadata_categorical,
            metadata_numeric=metadata_numeric,
        )
        decision_logits = self.decision_head(shared)
        threat_logits = self.binary_threat_head(shared).squeeze(-1)
        reason_logits = self.reason_head(shared)
        outputs = {
            "decision_logits": decision_logits,
            "threat_logits": threat_logits,
            "reason_logits": reason_logits,
            "pooled_embedding": pooled_embedding,
            "chunk_hidden": base_hidden.view(batch_size, self.recipe_config.top_k_chunks, -1).mean(dim=1),
        }
        if labels is None:
            return outputs

        decision_loss = deps["F"].cross_entropy(
            decision_logits,
            labels,
            weight=self.decision_loss_weights.to(decision_logits.device),
        )
        total_loss = decision_loss
        loss_breakdown: dict[str, float] = {"decision": float(decision_loss.detach().cpu())}
        if threat_labels is not None:
            threat_loss = deps["F"].binary_cross_entropy_with_logits(
                threat_logits,
                threat_labels.float(),
            )
            total_loss = total_loss + threat_loss
            loss_breakdown["binaryThreat"] = float(threat_loss.detach().cpu())
        if reason_labels is not None:
            reason_loss = deps["F"].binary_cross_entropy_with_logits(reason_logits, reason_labels.float())
            total_loss = total_loss + reason_loss
            loss_breakdown["reason"] = float(reason_loss.detach().cpu())
        contrastive_loss = self.contrastive_loss(pooled_embedding, labels)
        total_loss = total_loss + (contrastive_loss * 0.05)
        loss_breakdown["embedding"] = float(contrastive_loss.detach().cpu())
        outputs["loss"] = total_loss
        outputs["loss_breakdown"] = loss_breakdown
        return outputs


def build_recipe_expert_encoder(
    backbone: str,
    *,
    use_dora: bool,
    lora_rank: int,
    lora_alpha: int,
    lora_dropout: float,
) -> Any:
    deps = _require_model_dependencies()
    AutoModel = deps["AutoModel"]
    LoraConfig = deps["LoraConfig"]
    TaskType = deps["TaskType"]
    get_peft_model = deps["get_peft_model"]

    base_model = AutoModel.from_pretrained(backbone)
    peft_config = LoraConfig(
        task_type=TaskType.FEATURE_EXTRACTION,
        r=lora_rank,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        target_modules="all-linear",
        use_dora=use_dora,
    )
    return get_peft_model(base_model, peft_config)


def save_recipe_expert_artifact(
    output_dir: str | Path,
    *,
    model: Any,
    tokenizer: Any,
    config: RecipeExpertConfig,
    metadata_vocab: dict[str, dict[str, int]],
    include_tokenizer: bool,
) -> Path:
    deps = _require_model_dependencies()
    torch = deps["torch"]

    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    adapter_dir = target / "adapter"
    model.encoder.save_pretrained(adapter_dir)
    torch.save(
        {
            key: value.detach().cpu()
            for key, value in model.state_dict().items()
            if not key.startswith("encoder.")
        },
        target / "heads.pt",
    )
    (target / "recipe_expert.json").write_text(json.dumps(config.to_dict(), indent=2) + "\n", encoding="utf-8")
    (target / "metadata_vocab.json").write_text(json.dumps(metadata_vocab, indent=2) + "\n", encoding="utf-8")
    if include_tokenizer:
        tokenizer.save_pretrained(target / "tokenizer")
    return target


def load_recipe_expert_artifact(
    artifact_dir: str | Path,
    *,
    device: Any,
) -> tuple[Any, Any, RecipeExpertConfig, dict[str, dict[str, int]]]:
    deps = _require_model_dependencies()
    torch = deps["torch"]
    AutoModel = deps["AutoModel"]
    AutoTokenizer = deps["AutoTokenizer"]
    PeftModel = deps["PeftModel"]

    root = Path(artifact_dir)
    config = RecipeExpertConfig.from_dict(
        json.loads((root / "recipe_expert.json").read_text(encoding="utf-8"))
    )
    metadata_vocab = json.loads((root / "metadata_vocab.json").read_text(encoding="utf-8"))
    tokenizer_dir = root / "tokenizer"
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_dir if tokenizer_dir.is_dir() else config.backbone)
    base_model = AutoModel.from_pretrained(config.backbone)
    encoder = PeftModel.from_pretrained(base_model, root / "adapter", is_trainable=False)
    wrapper = HierarchicalActionGuardModel(encoder=encoder, config=config)
    state = torch.load(root / "heads.pt", map_location="cpu")
    wrapper.load_state_dict(state, strict=False)
    wrapper.to(device)
    wrapper.eval()
    return wrapper, tokenizer, config, metadata_vocab
