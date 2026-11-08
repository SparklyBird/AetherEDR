"""Behaviour baseline: Isolation Forest over per-process features.

Trained on the host's own process population (only processes that already had a memory
scan, so features are complete). Scores are normalised to 0..1 against the training
distribution: 0 = typical, 1 = beyond anything seen in training.

Caveat: unsupervised baselines learn whatever is already on the box. If the host is
compromised during training the attacker becomes "normal". Treat as one signal, not a verdict.
"""
from __future__ import annotations

import logging
import math
import threading

import numpy as np

from . import netintel
from .rules import SUSP_DIRS_POSIX, SUSP_DIRS_WIN

log = logging.getLogger("aether.anomaly")

FEATURES = [
    "cpu", "log_rss_mb", "log_threads", "rwx", "unbacked_exec", "susp_path_exec", "pe_in_private",
    "log_exec_mb", "log_net_out", "log_net_remotes", "net_listen", "depth", "log_cmdlen",
    "exe_susp_path", "log_exe_freq", "name_entropy",
]


def featurize(p: dict) -> list[float]:
    m = p.get("mem_summary") or {}
    exe = (p.get("exe") or "").lower()
    susp = exe.startswith(SUSP_DIRS_POSIX) or any(d in exe for d in SUSP_DIRS_WIN) or exe.startswith("/memfd:")
    return [
        min(float(p.get("last_cpu") or 0), 400.0),
        math.log1p((p.get("last_rss") or 0) / 1048576),
        math.log1p(p.get("last_threads") or 0),
        float(m.get("rwx_regions", 0)),
        float(m.get("unbacked_exec", 0)),
        float(m.get("susp_path_exec", 0)),
        float(m.get("pe_in_private", 0)),
        math.log1p((m.get("exec_bytes", 0)) / 1048576),
        math.log1p(p.get("net_out") or 0),
        math.log1p(p.get("net_remotes") or 0),
        float(p.get("net_listen") or 0),
        float(min(p.get("depth", 0), 12)),
        math.log1p(len(p.get("cmdline") or "")),
        1.0 if susp else 0.0,
        math.log1p(p.get("exe_freq", 1)),
        netintel.shannon(p.get("name") or ""),
    ]


class AnomalyEngine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model = None
        self._lo = 0.0
        self._hi = 1.0
        self._q99 = None      # per-feature 99.5th percentile of the training data
        self._scale = None    # per-feature scale for the out-of-range term
        self.trained_on = 0
        self.trained_at: float | None = None

    @property
    def ready(self) -> bool:
        return self._model is not None

    def train(self, rows: list[dict], min_samples: int = 400) -> bool:
        if len(rows) < min_samples:
            return False
        from sklearn.ensemble import IsolationForest  # noqa: PLC0415 (slow import, defer)

        X = np.array([featurize(r) for r in rows], dtype=float)
        model = IsolationForest(n_estimators=150, max_samples=min(256, len(X)), contamination="auto",
                                random_state=7, n_jobs=1)
        model.fit(X)
        raw = -model.score_samples(X)             # higher = more anomalous
        lo, hi = float(np.percentile(raw, 90)), float(raw.max())
        if hi - lo < 1e-6:
            hi = lo + 1e-6
        q99 = np.percentile(X, 99.5, axis=0)
        scale = np.maximum(X.std(axis=0), 1.0)
        with self._lock:
            self._model, self._lo, self._hi = model, lo, hi
            self._q99, self._scale = q99, scale
            self.trained_on = len(X)
            import time  # noqa: PLC0415

            self.trained_at = time.time()
        log.info("baseline trained on %d processes", len(X))
        return True

    def score(self, p: dict) -> float | None:
        out = self.score_many([p])
        return out[0]

    def score_many(self, rows: list[dict]) -> list[float | None]:
        """anomaly = max(isolation-forest score, out-of-range score).

        Isolation Forest cannot isolate a value on a feature that was constant in training
        (e.g. every baseline process had zero RWX regions), so a second term measures how far
        each feature exceeds its training 99.5th percentile.
        """
        with self._lock:
            model, lo, hi, q99, scale = self._model, self._lo, self._hi, self._q99, self._scale
        if model is None or not rows:
            return [None] * len(rows)
        X = np.array([featurize(r) for r in rows], dtype=float)
        iso = np.clip((-model.score_samples(X) - lo) / (hi - lo), 0.0, 1.0)
        exceed = np.clip((X - q99) / scale, 0.0, 6.0).sum(axis=1)
        rng = 1.0 - np.exp(-exceed / 2.0)
        return [float(v) for v in np.maximum(iso, rng)]


engine = AnomalyEngine()
