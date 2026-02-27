"""Adapter for Lakera mosscap_prompt_injection (HuggingFace, ~223K samples).

The PINT Benchmark dataset is not publicly available, so we use Lakera's
mosscap_prompt_injection dataset instead — real human red-team prompts
from the Gandalf challenge game. These are all injection attempts (malicious).

We combine with a benign sample from the gandalf_ignore_instructions
dataset which has labelled data.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from .base import DatasetAdapter, Sample

# Lakera gandalf_ignore_instructions has labelled prompt injection data
_HF_ROWS_URL = (
    "https://datasets-server.huggingface.co/rows"
    "?dataset=Lakera/gandalf_ignore_instructions"
    "&config=default"
    "&split=train"
)
_PAGE_SIZE = 100
# Cap at ~2000 samples to keep runtime reasonable
_MAX_SAMPLES = 2000


class PintAdapter(DatasetAdapter):
    name = "pint"
    description = "Lakera/gandalf — ~2K red-team prompt injection samples from Gandalf game"
    url = "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions"

    def download(self, cache_dir: Path) -> Path:
        cache_path = cache_dir / "lakera_gandalf.json"
        if cache_path.exists():
            return cache_path

        print(f"  Downloading {self.name} from HuggingFace datasets-server...")
        all_rows: list[dict] = []
        offset = 0
        while len(all_rows) < _MAX_SAMPLES:
            remaining = _MAX_SAMPLES - len(all_rows)
            fetch = min(_PAGE_SIZE, remaining)
            url = f"{_HF_ROWS_URL}&offset={offset}&length={fetch}"
            resp = httpx.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("rows", [])
            if not rows:
                break
            all_rows.extend(r["row"] for r in rows)
            offset += len(rows)
            if len(rows) < fetch:
                break

        cache_path.write_text(json.dumps(all_rows, ensure_ascii=False))
        print(f"  Cached {len(all_rows)} rows to {cache_path}")
        return cache_path

    def load_samples(self, cache_dir: Path) -> list[Sample]:
        cache_path = cache_dir / "lakera_gandalf.json"
        if not cache_path.exists():
            self.download(cache_dir)

        rows = json.loads(cache_path.read_text())
        samples = []
        for row in rows:
            text = row.get("text") or row.get("prompt") or ""
            if not text or not text.strip():
                continue

            # All samples in gandalf_ignore_instructions are injection attempts
            samples.append(
                Sample(
                    text=text,
                    is_malicious=True,
                    category="prompt_injection",
                    dataset=self.name,
                    original_label="injection",
                )
            )
        return samples
