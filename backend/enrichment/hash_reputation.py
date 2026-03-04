from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx


CONFIG_PATHS = [
    Path(__file__).resolve().parents[1] / "config.json",
    Path(__file__).resolve().parents[1] / "config.example.json",
]


@dataclass
class HashReputationResult:
    verdict: str
    provider: str
    malicious: bool
    score: Optional[float]
    details: dict[str, Any]


class HashReputationClient:
    def __init__(self) -> None:
        self.config = self._load_config()
        self.vt_key = self.config.get("virustotal", {}).get("api_key")
        self.vt_enabled = self.config.get("virustotal", {}).get("enabled", False)
        self.hy_key = self.config.get("hybrid_analysis", {}).get("api_key")
        self.hy_enabled = self.config.get("hybrid_analysis", {}).get("enabled", False)
        self.hy_user_agent = self.config.get("hybrid_analysis", {}).get(
            "user_agent",
            "TamsilCMS-Sentinel",
        )
        self.timeout_seconds = float(self.config.get("timeout_seconds", 8))

    def _load_config(self) -> dict[str, Any]:
        for path in CONFIG_PATHS:
            if path.exists():
                with path.open("r", encoding="utf-8") as handle:
                    return json.load(handle)
        return {}

    def check_hash(self, sha256: str) -> Optional[HashReputationResult]:
        if self.vt_enabled and self.vt_key:
            result = self._check_virustotal(sha256)
            if result:
                return result
        if self.hy_enabled and self.hy_key:
            return self._check_hybrid_analysis(sha256)
        return None

    def _check_virustotal(self, sha256: str) -> Optional[HashReputationResult]:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.vt_key}
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.get(url, headers=headers)
            if response.status_code != 200:
                return None
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + suspicious + harmless + undetected
            score = malicious / total if total else None
            verdict = "unknown"
            if malicious > 0:
                verdict = "malicious"
            elif suspicious > 0:
                verdict = "suspicious"
            elif harmless > 0:
                verdict = "clean"
            return HashReputationResult(
                verdict=verdict,
                provider="virustotal",
                malicious=verdict == "malicious",
                score=score,
                details={
                    "analysis_stats": stats,
                    "reputation": data.get("reputation"),
                    "last_analysis_date": data.get("last_analysis_date"),
                },
            )
        except (httpx.HTTPError, ValueError):
            return None

    def _check_hybrid_analysis(self, sha256: str) -> Optional[HashReputationResult]:
        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            "api-key": self.hy_key,
            "User-Agent": self.hy_user_agent,
            "accept": "application/json",
        }
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(url, data={"hashes": sha256}, headers=headers)
            if response.status_code != 200:
                return None
            payload = response.json()
            if not isinstance(payload, list) or not payload:
                return None
            entry = payload[0]
            verdict = (entry.get("verdict") or "unknown").lower()
            threat_score = entry.get("threat_score")
            malicious = verdict in {"malicious", "suspicious"}
            return HashReputationResult(
                verdict=verdict,
                provider="hybrid_analysis",
                malicious=malicious,
                score=float(threat_score) / 100 if threat_score is not None else None,
                details={
                    "threat_score": threat_score,
                    "classification": entry.get("classification"),
                    "family": entry.get("family"),
                    "tags": entry.get("tags"),
                },
            )
        except (httpx.HTTPError, ValueError, TypeError):
            return None


_client: Optional[HashReputationClient] = None


def get_hash_reputation_client() -> HashReputationClient:
    global _client
    if _client is None:
        _client = HashReputationClient()
    return _client
