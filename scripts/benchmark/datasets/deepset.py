"""Adapter for deepset/prompt-injections (HuggingFace, ~662 samples)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from .base import DatasetAdapter, Sample

_HF_ROWS_URL = (
    "https://datasets-server.huggingface.co/rows"
    "?dataset=deepset/prompt-injections"
    "&config=default"
    "&split=train"
)
_PAGE_SIZE = 100


class DeepsetAdapter(DatasetAdapter):
    name = "deepset"
    description = "deepset/prompt-injections — 662 samples, binary injection/benign"
    url = "https://huggingface.co/datasets/deepset/prompt-injections"

    def download(self, cache_dir: Path) -> Path:
        cache_path = cache_dir / "deepset_prompt_injections.json"
        if cache_path.exists():
            return cache_path

        print(f"  Downloading {self.name} from HuggingFace datasets-server...")
        all_rows: list[dict] = []
        offset = 0
        while True:
            url = f"{_HF_ROWS_URL}&offset={offset}&length={_PAGE_SIZE}"
            resp = httpx.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("rows", [])
            if not rows:
                break
            all_rows.extend(r["row"] for r in rows)
            offset += len(rows)
            if len(rows) < _PAGE_SIZE:
                break

        cache_path.write_text(json.dumps(all_rows, ensure_ascii=False))
        print(f"  Cached {len(all_rows)} rows to {cache_path}")
        return cache_path

    def load_samples(self, cache_dir: Path) -> list[Sample]:
        cache_path = cache_dir / "deepset_prompt_injections.json"
        if not cache_path.exists():
            self.download(cache_dir)

        rows = json.loads(cache_path.read_text())
        samples = []
        for row in rows:
            text = row.get("text", "")
            if not text or not text.strip():
                continue
            label = row.get("label", 0)
            samples.append(
                Sample(
                    text=text,
                    is_malicious=label == 1,
                    category="prompt_injection" if label == 1 else "benign",
                    dataset=self.name,
                    original_label=str(label),
                )
            )
        return samples
