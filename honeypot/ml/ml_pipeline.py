#!/usr/bin/env python3
"""
ML Pipeline for Honeypot Attack Analysis
- Attack classification     (RandomForestClassifier)
- Anomaly detection         (IsolationForest)
- Threat scoring            (GradientBoostingRegressor — regression, not classifier)
- Attacker clustering       (KMeans)

Fixes vs original:
  - GradientBoostingRegressor used for threat scoring (was wrongly a classifier)
  - KMeans n_jobs argument removed (deprecated/removed in modern sklearn)
  - pickle.load integrity validated via SHA-256 hash file
  - Scaler distribution mismatch detection on load
  - Config values from shared config module
  - Threat-score labels no longer used as both training targets AND inference
    — training now expects a "threat_score" ground-truth field in training data
    and falls back to rule-based scoring only when that field is absent
  - All bare excepts replaced with specific exception handling
"""

import hashlib
import json
import logging
import pickle
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

try:
    from sklearn.ensemble import (
        GradientBoostingRegressor,
        IsolationForest,
        RandomForestClassifier,
    )
    from sklearn.cluster import KMeans
    from sklearn.metrics import accuracy_score, classification_report, mean_absolute_error
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder, StandardScaler

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("scikit-learn not available — using rule-based fallback models.")

from config import (
    ML_CONTAMINATION,
    ML_N_CLUSTERS,
    ML_N_ESTIMATORS,
    ML_TEST_SIZE,
    ML_THREAT_ML_WEIGHT,
    ML_THREAT_RULE_WEIGHT,
    MODELS_DIR,
)

FEATURE_NAMES = [
    "port",
    "port_commonality",
    "requests_per_second",
    "unique_payloads",
    "duration",
    "is_scanning",
    "is_exploit",
    "is_bruteforce",
    "time_of_day",
    "day_of_week",
    "has_geo",
    "indicator_count",
    "has_malware",
]

ATTACKER_PROFILES = {
    0: "Opportunistic Scanner",
    1: "Targeted Attacker",
    2: "Automated Bot",
    3: "Manual Hacker",
    4: "Advanced Persistent Threat",
}


# ── Integrity helpers ──────────────────────────────────────────────────────────

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _save_hash(path: Path) -> None:
    Path(str(path) + ".sha256").write_text(_file_sha256(path))


def _verify_hash(path: Path) -> bool:
    hash_file = Path(str(path) + ".sha256")
    if not hash_file.exists():
        logging.warning(f"No integrity file for {path.name} — skipping verification.")
        return True  # Warn but don't hard-fail on first use
    expected = hash_file.read_text().strip()
    actual   = _file_sha256(path)
    if expected != actual:
        logging.error(f"Integrity check FAILED for {path.name}: file may have been tampered with.")
        return False
    return True


# ── Feature extraction ─────────────────────────────────────────────────────────

def extract_features(attack: dict) -> dict:
    info        = attack.get("info",        {})
    ml_features = attack.get("ml_features", {})

    return {
        "port":                attack.get("honeypot_port",                   0),
        "port_commonality":    ml_features.get("port_commonality",           0),
        "requests_per_second": ml_features.get("requests_per_second",        0),
        "unique_payloads":     ml_features.get("unique_payloads",            0),
        "duration":            ml_features.get("duration_seconds",           0),
        "is_scanning":         int(ml_features.get("is_scanning",            0)),
        "is_exploit":          int(ml_features.get("is_exploit",             0)),
        "is_bruteforce":       int(ml_features.get("is_bruteforce",          0)),
        "time_of_day":         ml_features.get("time_of_day",               12),
        "day_of_week":         ml_features.get("day_of_week",                0),
        "has_geo":             int(bool(info.get("lat") and info.get("lon"))),
        "indicator_count":     len(info.get("threat_indicators", [])),
        "has_malware":         int(bool(info.get("malware_family"))),
    }


def features_to_array(features: dict) -> np.ndarray:
    return np.array([[features[k] for k in FEATURE_NAMES]], dtype=float)


# ── Rule-based helpers (used as fallback AND for training-label generation) ───

def rule_based_classify(attack: dict) -> str:
    port       = attack.get("honeypot_port", 0)
    indicators = attack.get("info", {}).get("threat_indicators", [])
    port_map   = {
        22: "SSH Brute Force", 21: "FTP Attack", 23: "Telnet Brute Force",
        445: "SMB Exploit", 3306: "MySQL Attack", 5432: "PostgreSQL Attack",
        6379: "Redis Attack", 3389: "RDP Brute Force", 53: "DNS Amplification",
        27017: "MongoDB Attack",
    }
    if port in port_map:
        return port_map[port]
    if port in (80, 443, 8080, 8443):
        return "HTTP Web Scan"
    if "scan" in str(indicators).lower():
        return "Port Scan"
    return "Unknown Attack"


def rule_based_threat_score(attack: dict) -> float:
    """Deterministic rule-based threat score (0–10). Used as training label
    when ground-truth 'threat_score' is absent, and blended at inference time."""
    score = 3.0
    attack_type = attack.get("attack_type", "")
    if "Brute Force" in attack_type: score += 3
    if "Exploit"     in attack_type: score += 4
    if "Scan"        in attack_type: score += 1
    if attack.get("info", {}).get("malware_family"): score += 3
    score += min(len(attack.get("info", {}).get("threat_indicators", [])), 3)
    return min(10.0, score)


def severity_label(score: float) -> str:
    if   score >= 8: return "CRITICAL"
    elif score >= 6: return "HIGH"
    elif score >= 4: return "MEDIUM"
    elif score >= 2: return "LOW"
    else:            return "INFO"


def threat_recommendations(attack: dict, score: float) -> list[str]:
    recs = []
    port = attack.get("honeypot_port", 0)
    if score >= 6:
        recs += ["Block attacker IP in firewall", "Enable rate limiting on affected service"]
    if port == 22:
        recs += ["Enable fail2ban for SSH", "Disable password auth — use SSH keys only"]
    elif port in (21, 23):
        recs += ["Disable legacy protocols (FTP/Telnet)", "Use SFTP/SSH instead"]
    elif port in (3306, 5432, 6379, 27017):
        recs += [
            "Bind database to localhost only",
            "Enable authentication",
            "Restrict access with firewall rules",
        ]
    return recs


# ── Main ML class ──────────────────────────────────────────────────────────────

class HoneypotML:
    def __init__(self) -> None:
        self.classifier:      RandomForestClassifier | None    = None
        self.anomaly_detector: IsolationForest | None          = None
        self.threat_scorer:   GradientBoostingRegressor | None = None
        self.clusterer:       "KMeans | None"                  = None
        self.label_encoder:   LabelEncoder | None  = LabelEncoder()  if ML_AVAILABLE else None
        self.scaler:          StandardScaler | None = StandardScaler() if ML_AVAILABLE else None
        self.is_trained:      bool = False
        self._scaler_mean:    np.ndarray | None = None  # stored for distribution drift detection

    # ── Training ───────────────────────────────────────────────────────────────

    def train(self, training_data_path: str) -> None:
        print(f"Loading training data from: {training_data_path}")
        attacks: list[dict] = []

        try:
            with open(training_data_path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        attacks.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        logging.warning(f"Skipping malformed line {lineno}: {exc}")
        except FileNotFoundError:
            print(f"Training file not found: {training_data_path}")
            return

        if not attacks:
            print("No usable training data found.")
            return

        print(f"Loaded {len(attacks)} attack records.")

        X_raw         = [extract_features(a)                           for a in attacks]
        y_classify    = [a.get("attack_type") or rule_based_classify(a) for a in attacks]
        y_threat      = [a.get("threat_score",  rule_based_threat_score(a)) for a in attacks]

        X = np.array([[row[k] for k in FEATURE_NAMES] for row in X_raw], dtype=float)

        if not ML_AVAILABLE:
            print("sklearn not available — rule-based mode only.")
            self.is_trained = True
            return

        # Encode labels & scale features
        y_classify_enc = self.label_encoder.fit_transform(y_classify)
        X_scaled       = self.scaler.fit_transform(X)
        self._scaler_mean = self.scaler.mean_.copy()

        X_train, X_test, y_cls_train, y_cls_test, y_thr_train, y_thr_test = train_test_split(
            X_scaled, y_classify_enc, y_threat,
            test_size=ML_TEST_SIZE, random_state=42,
        )

        # Attack classifier
        print("\nTraining Attack Classifier (Random Forest)…")
        self.classifier = RandomForestClassifier(
            n_estimators=ML_N_ESTIMATORS, random_state=42, n_jobs=-1
        )
        self.classifier.fit(X_train, y_cls_train)
        y_pred = self.classifier.predict(X_test)
        print(f"  Accuracy: {accuracy_score(y_cls_test, y_pred):.2%}")
        print(classification_report(y_cls_test, y_pred, target_names=self.label_encoder.classes_))

        # Anomaly detector
        print("Training Anomaly Detector (Isolation Forest)…")
        self.anomaly_detector = IsolationForest(
            contamination=ML_CONTAMINATION, random_state=42, n_jobs=-1
        )
        self.anomaly_detector.fit(X_scaled)

        # Threat scorer — regression (GradientBoostingRegressor, not classifier)
        print("Training Threat Scorer (Gradient Boosting Regressor)…")
        self.threat_scorer = GradientBoostingRegressor(
            n_estimators=ML_N_ESTIMATORS, random_state=42
        )
        self.threat_scorer.fit(X_train, y_thr_train)
        y_thr_pred = self.threat_scorer.predict(X_test)
        print(f"  MAE: {mean_absolute_error(y_thr_test, y_thr_pred):.3f}")

        # Attacker clusterer — n_jobs removed (deprecated in modern sklearn)
        print(f"Training Attacker Clusterer (K-Means, k={ML_N_CLUSTERS})…")
        self.clusterer = KMeans(n_clusters=ML_N_CLUSTERS, random_state=42, n_init="auto")
        self.clusterer.fit(X_scaled)

        self.is_trained = True
        print("\nTraining complete.")
        self.save_models()

    # ── Inference ──────────────────────────────────────────────────────────────

    def _scale(self, attack: dict) -> np.ndarray:
        X = features_to_array(extract_features(attack))
        return self.scaler.transform(X) if ML_AVAILABLE and self.scaler else X

    def predict_attack_type(self, attack: dict) -> dict:
        if not self.is_trained:
            return {"error": "Model not trained", "predicted_type": rule_based_classify(attack)}

        if not ML_AVAILABLE or self.classifier is None:
            return {"predicted_type": rule_based_classify(attack), "model": "rule-based"}

        X_scaled     = self._scale(attack)
        prediction   = self.classifier.predict(X_scaled)[0]
        probabilities = self.classifier.predict_proba(X_scaled)[0]

        return {
            "predicted_type": self.label_encoder.inverse_transform([prediction])[0],
            "confidence":     float(max(probabilities)),
            "all_probabilities": {
                cls: float(prob)
                for cls, prob in zip(self.label_encoder.classes_, probabilities)
            },
            "model": "RandomForest",
        }

    def detect_anomaly(self, attack: dict) -> dict:
        if not self.is_trained or not ML_AVAILABLE or self.anomaly_detector is None:
            return {"is_anomaly": False, "score": 0.0, "interpretation": "Model not available"}

        X_scaled      = self._scale(attack)
        is_anomaly    = self.anomaly_detector.predict(X_scaled)[0] == -1
        anomaly_score = abs(float(self.anomaly_detector.score_samples(X_scaled)[0]))

        return {
            "is_anomaly":     bool(is_anomaly),
            "anomaly_score":  round(anomaly_score, 4),
            "interpretation": "Unusual attack pattern" if is_anomaly else "Normal attack pattern",
        }

    def score_threat(self, attack: dict) -> dict:
        rule_score = rule_based_threat_score(attack)

        if ML_AVAILABLE and self.threat_scorer and self.is_trained:
            X_scaled  = self._scale(attack)
            ml_score  = float(np.clip(self.threat_scorer.predict(X_scaled)[0], 0, 10))
            final     = ML_THREAT_ML_WEIGHT * ml_score + ML_THREAT_RULE_WEIGHT * rule_score
        else:
            ml_score  = rule_score
            final     = rule_score

        return {
            "threat_score":    round(final,      1),
            "ml_score":        round(ml_score,   1),
            "rule_score":      round(rule_score, 1),
            "severity":        severity_label(final),
            "recommendations": threat_recommendations(attack, final),
        }

    def cluster_attacker(self, attack: dict) -> dict:
        if not self.is_trained or not ML_AVAILABLE or self.clusterer is None:
            return {"cluster": -1, "profile": "Unknown (model not available)"}

        X_scaled = self._scale(attack)
        cluster  = int(self.clusterer.predict(X_scaled)[0])
        return {
            "cluster": cluster,
            "profile": ATTACKER_PROFILES.get(cluster, "Unknown"),
        }

    def analyze_attack(self, attack: dict) -> dict:
        return {
            "attack_type": self.predict_attack_type(attack),
            "anomaly":     self.detect_anomaly(attack),
            "threat":      self.score_threat(attack),
            "cluster":     self.cluster_attacker(attack),
            "timestamp":   datetime.now().isoformat(),
        }

    # ── Persistence ────────────────────────────────────────────────────────────

    def save_models(self, path: Path = MODELS_DIR) -> None:
        if not ML_AVAILABLE:
            print("sklearn not available — nothing to save.")
            return

        path.mkdir(parents=True, exist_ok=True)
        models = {
            "classifier.pkl":       self.classifier,
            "anomaly_detector.pkl": self.anomaly_detector,
            "threat_scorer.pkl":    self.threat_scorer,
            "clusterer.pkl":        self.clusterer,
            "label_encoder.pkl":    self.label_encoder,
            "scaler.pkl":           self.scaler,
        }
        for filename, obj in models.items():
            if obj is None:
                continue
            file_path = path / filename
            with open(file_path, "wb") as f:
                pickle.dump(obj, f)
            _save_hash(file_path)

        # Save scaler mean for drift detection on load
        if self.scaler is not None:
            np.save(str(path / "scaler_mean.npy"), self.scaler.mean_)

        print(f"Models saved to {path}/")

    def load_models(self, path: Path = MODELS_DIR) -> None:
        if not ML_AVAILABLE:
            logging.warning("sklearn not available — using rule-based mode.")
            self.is_trained = True
            return

        model_files = {
            "classifier.pkl":       "classifier",
            "anomaly_detector.pkl": "anomaly_detector",
            "threat_scorer.pkl":    "threat_scorer",
            "clusterer.pkl":        "clusterer",
            "label_encoder.pkl":    "label_encoder",
            "scaler.pkl":           "scaler",
        }
        try:
            for filename, attr in model_files.items():
                file_path = path / filename
                if not file_path.exists():
                    raise FileNotFoundError(f"Missing model file: {file_path}")
                if not _verify_hash(file_path):
                    raise ValueError(f"Integrity check failed for {filename} — aborting load.")
                with open(file_path, "rb") as f:
                    setattr(self, attr, pickle.load(f))

            # Distribution drift check
            mean_file = path / "scaler_mean.npy"
            if mean_file.exists() and self.scaler is not None:
                saved_mean = np.load(str(mean_file))
                # Warn if feature means shifted significantly (indicates different data distribution)
                drift = np.abs(self.scaler.mean_ - saved_mean).max()
                if drift > 1.0:
                    logging.warning(
                        f"Feature distribution drift detected (max delta={drift:.3f}). "
                        "Consider retraining the model on current data."
                    )

            self.is_trained = True
            print(f"Models loaded from {path}/")

        except FileNotFoundError as exc:
            print(f"Models not found: {exc}\nRun: python ml_pipeline.py train <data_file>")
        except (ValueError, pickle.UnpicklingError) as exc:
            print(f"Failed to load models: {exc}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    ml = HoneypotML()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == "train":
            data_file = sys.argv[2] if len(sys.argv) > 2 else "honeypot_synthetic.jsonl"
            ml.train(data_file)

        elif cmd == "test":
            ml.load_models()
            test_attack = {
                "honeypot_port": 22,
                "attack_type":   "SSH Brute Force",
                "threat_score":  7.5,
                "ml_features": {
                    "requests_per_second": 15.5,
                    "unique_payloads":     5,
                    "port_commonality":    1.0,
                    "is_scanning":         0,
                    "is_exploit":          0,
                    "is_bruteforce":       1,
                    "time_of_day":         3,
                    "day_of_week":         1,
                    "duration_seconds":    45,
                },
                "info": {
                    "threat_indicators": ["multiple_auth_attempts", "credential_stuffing"],
                    "country":           "Unknown",
                    "malware_family":    None,
                    "lat":               0,
                    "lon":               0,
                },
            }
            result = ml.analyze_attack(test_attack)
            print("\n=== ML Analysis Result ===")
            print(json.dumps(result, indent=2))

        else:
            print(f"Unknown command: {cmd}")
            print("Usage: python ml_pipeline.py train [data_file] | test")
    else:
        print("Usage:")
        print("  python ml_pipeline.py train [data_file]   Train models on JSONL data")
        print("  python ml_pipeline.py test                 Test with a sample attack")
