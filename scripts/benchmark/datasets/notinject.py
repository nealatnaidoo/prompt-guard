"""Adapter for NotInject false-positive calibration dataset (GitHub, ~339 samples).

Data is split across 3 files in the InjecGuard repo:
- NotInject_one.json (113 samples, 1 trigger word each)
- NotInject_two.json (113 samples, 2 trigger words each)
- NotInject_three.json (113 samples, 3 trigger words each)

Each sample has: prompt, word_list, category. ALL are benign.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from .base import DatasetAdapter, Sample

_GITHUB_BASE = (
    "https://raw.githubusercontent.com/SaFoLab-WISC/InjecGuard/main/datasets"
)
_FILES = ["NotInject_one.json", "NotInject_two.json", "NotInject_three.json"]


class NotInjectAdapter(DatasetAdapter):
    name = "notinject"
    description = "NotInject — 339 benign samples with trigger words (false-positive calibration)"
    url = "https://github.com/SaFoLab-WISC/InjecGuard"

    def download(self, cache_dir: Path) -> Path:
        cache_path = cache_dir / "notinject.json"
        if cache_path.exists():
            return cache_path

        print(f"  Downloading {self.name} from GitHub (3 files)...")

        all_rows: list[dict] = []
        for filename in _FILES:
            url = f"{_GITHUB_BASE}/{filename}"
            resp = httpx.get(url, timeout=30, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                all_rows.extend(data)
            else:
                all_rows.append(data)
            print(f"    {filename}: {len(data) if isinstance(data, list) else 1} samples")

        cache_path.write_text(json.dumps(all_rows, ensure_ascii=False))
        print(f"  Cached {len(all_rows)} rows to {cache_path}")
        return cache_path

    def load_samples(self, cache_dir: Path) -> list[Sample]:
        cache_path = cache_dir / "notinject.json"
        if not cache_path.exists():
            self.download(cache_dir)

        rows = json.loads(cache_path.read_text())
        samples = []
        for row in rows:
            text = row.get("prompt") or row.get("text") or row.get("sentence", "")
            if not text or not text.strip():
                continue

            category = row.get("category", "benign")

            # ALL NotInject samples are benign — that's the whole point.
            # Any detection is a false positive.
            samples.append(
                Sample(
                    text=text,
                    is_malicious=False,
                    category=str(category),
                    dataset=self.name,
                    original_label="benign",
                )
            )
        return samples
