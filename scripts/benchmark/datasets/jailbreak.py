"""Adapter for jackhhao/jailbreak-classification (HuggingFace, ~1.3K samples)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from .base import DatasetAdapter, Sample

_HF_ROWS_URL = (
    "https://datasets-server.huggingface.co/rows"
    "?dataset=jackhhao/jailbreak-classification"
    "&config=default"
    "&split=train"
)
_PAGE_SIZE = 100


class JailbreakAdapter(DatasetAdapter):
    name = "jailbreak"
    description = "jackhhao/jailbreak-classification — ~1.3K samples, binary jailbreak/benign"
    url = "https://huggingface.co/datasets/jackhhao/jailbreak-classification"

    def download(self, cache_dir: Path) -> Path:
        cache_path = cache_dir / "jailbreak_classification.json"
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
        cache_path = cache_dir / "jailbreak_classification.json"
        if not cache_path.exists():
            self.download(cache_dir)

        rows = json.loads(cache_path.read_text())
        samples = []
        for row in rows:
            # Field names vary: "prompt", "text", "content"
            text = row.get("prompt") or row.get("text") or row.get("content", "")
            if not text or not text.strip():
                continue

            # Label field: "type" or "label"
            label = str(row.get("type") or row.get("label", "")).lower().strip()
            is_malicious = label in ("jailbreak", "1", "true", "malicious")

            samples.append(
                Sample(
                    text=text,
                    is_malicious=is_malicious,
                    category="jailbreak" if is_malicious else "benign",
                    dataset=self.name,
                    original_label=label,
                )
            )
        return samples
