import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json
import pickle
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
import hashlib

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

logger = logging.getLogger(__name__)


@dataclass
class ModelMetadata:
    """Model metadata"""
    model_id: str
    model_type: str  # anomaly, classifier, lstm, autoencoder
    feature_set: str
    created_at: str
    training_samples: int
    validation_samples: int
    metrics: Dict[str, Any]
    hyperparameters: Dict[str, Any]
    feature_names: List[str]
    threshold: Optional[float] = None
    classes: Optional[List[str]] = None


class FeatureExtractor:
    """Extract features from EDR events"""
    
    # Feature set definitions
    FEATURE_SETS = {
        "process_behavioral": {
            "numerical": [
                "process_lifetime_seconds",
                "child_process_count",
                "network_connections_count",
                "file_operations_count",
                "registry_operations_count",
                "command_line_length",
                "command_line_entropy",
                "cpu_usage_percent",
                "memory_usage_mb"
            ],
            "categorical": [
                "process_name",
                "parent_process_name",
                "user_account",
                "integrity_level",
                "is_signed"
            ],
            "temporal": [
                "hour_of_day",
                "day_of_week",
                "is_business_hours"
            ]
        },
        "network_behavioral": {
            "numerical": [
                "bytes_sent",
                "bytes_received",
                "connection_duration_seconds",
                "connections_per_minute",
                "unique_destinations_count",
                "destination_port"
            ],
            "categorical": [
                "protocol",
                "destination_country",
                "is_internal_ip",
                "is_known_good_domain"
            ],
            "derived": [
                "upload_download_ratio",
                "is_unusual_port"
            ]
        },
        "file_behavioral": {
            "numerical": [
                "file_size_bytes",
                "file_entropy",
                "operations_per_minute"
            ],
            "categorical": [
                "file_extension",
                "operation_type",
                "file_location_category",
                "is_executable",
                "is_signed"
            ]
        }
    }
    
    def __init__(self, feature_set_name: str):
        if feature_set_name not in self.FEATURE_SETS:
            raise ValueError(f"Unknown feature set: {feature_set_name}")
        
        self.feature_set_name = feature_set_name
        self.feature_set = self.FEATURE_SETS[feature_set_name]
        self.label_encoders = {}
        self.scaler = StandardScaler()
    
    def extract(self, events: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        """Extract features from events"""
        df = pd.DataFrame(events)
        
        # Extract all feature types
        features = []
        feature_names = []
        
        # Numerical features
        if "numerical" in self.feature_set:
            for feature in self.feature_set["numerical"]:
                if feature in df.columns:
                    features.append(df[feature].fillna(0).values)
                    feature_names.append(feature)
        
        # Categorical features (label encoded)
        if "categorical" in self.feature_set:
            for feature in self.feature_set["categorical"]:
                if feature in df.columns:
                    if feature not in self.label_encoders:
                        self.label_encoders[feature] = LabelEncoder()
                        encoded = self.label_encoders[feature].fit_transform(
                            df[feature].fillna("unknown").astype(str)
                        )
                    else:
                        # Handle unseen labels
                        encoded = []
                        for val in df[feature].fillna("unknown").astype(str):
                            try:
                                encoded.append(self.label_encoders[feature].transform([val])[0])
                            except ValueError:
                                encoded.append(-1)  # Unknown category
                        encoded = np.array(encoded)
                    
                    features.append(encoded)
                    feature_names.append(f"{feature}_encoded")
        
        # Temporal features
        if "temporal" in self.feature_set:
            if "timestamp" in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                features.append(df['timestamp'].dt.hour.values)
                feature_names.append("hour_of_day")
                features.append(df['timestamp'].dt.dayofweek.values)
                feature_names.append("day_of_week")
                is_business = ((df['timestamp'].dt.hour >= 8) & 
                              (df['timestamp'].dt.hour <= 17) &
                              (df['timestamp'].dt.dayofweek < 5)).astype(int).values
                features.append(is_business)
                feature_names.append("is_business_hours")
        
        # Derived features
        if "derived" in self.feature_set:
            for feature in self.feature_set["derived"]:
                if feature == "upload_download_ratio":
                    ratio = df['bytes_sent'] / (df['bytes_received'] + 1)
                    features.append(ratio.fillna(0).values)
                    feature_names.append(feature)
                elif feature == "is_unusual_port":
                    common_ports = [80, 443, 22, 21, 25, 110, 143, 3389]
                    is_unusual = (~df['destination_port'].isin(common_ports)).astype(int).values
                    features.append(is_unusual)
                    feature_names.append(feature)
        
        # Stack features
        if not features:
            raise ValueError("No features extracted")
        
        X = np.column_stack(features)
        
        return X, feature_names
    
    def get_feature_names(self) -> List[str]:
        """Get feature names after extraction"""
        feature_names = []
        
        if "numerical" in self.feature_set:
            feature_names.extend(self.feature_set["numerical"])
        
        if "categorical" in self.feature_set:
            feature_names.extend([f"{f}_encoded" for f in self.feature_set["categorical"]])
        
        if "temporal" in self.feature_set:
            feature_names.extend(["hour_of_day", "day_of_week", "is_business_hours"])
        
        if "derived" in self.feature_set:
            feature_names.extend(self.feature_set["derived"])
        
        return feature_names


class AnomalyDetectionTrainer:
    """Train anomaly detection models using Isolation Forest"""
    
    def __init__(self, feature_extractor: FeatureExtractor):
        self.feature_extractor = feature_extractor
        self.model = None
        self.threshold = None
    
    def train(
        self,
        training_data: List[Dict[str, Any]],
        validation_split: float = 0.2,
        contamination: float = 0.1,
        **kwargs
    ) -> ModelMetadata:
        """Train anomaly detection model"""
        logger.info(f"Training anomaly detection model on {len(training_data)} samples")
        
        # Extract features
        X, feature_names = self.feature_extractor.extract(training_data)
        
        # Scale features
        X_scaled = self.feature_extractor.scaler.fit_transform(X)
        
        # Split data
        X_train, X_val = train_test_split(
            X_scaled,
            test_size=validation_split,
            random_state=42
        )
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=kwargs.get('n_estimators', 100),
            max_samples=kwargs.get('max_samples', 'auto'),
            n_jobs=-1
        )
        
        train_start = datetime.utcnow()
        self.model.fit(X_train)
        training_time = (datetime.utcnow() - train_start).total_seconds()
        
        # Validate
        val_predictions = self.model.predict(X_val)
        val_scores = self.model.score_samples(X_val)
        
        # Calculate threshold (using validation set)
        self.threshold = np.percentile(val_scores, contamination * 100)
        
        # Metrics
        anomaly_count = np.sum(val_predictions == -1)
        anomaly_rate = anomaly_count / len(val_predictions)
        
        metrics = {
            "validation_anomaly_rate": float(anomaly_rate),
            "threshold": float(self.threshold),
            "training_time_seconds": round(training_time, 2),
            "samples_count": len(training_data)
        }
        
        # Generate model ID
        model_id = self._generate_model_id("anomaly", self.feature_extractor.feature_set_name)
        
        metadata = ModelMetadata(
            model_id=model_id,
            model_type="anomaly",
            feature_set=self.feature_extractor.feature_set_name,
            created_at=datetime.utcnow().isoformat(),
            training_samples=len(X_train),
            validation_samples=len(X_val),
            metrics=metrics,
            hyperparameters={
                "contamination": contamination,
                "n_estimators": self.model.n_estimators,
                "max_samples": self.model.max_samples
            },
            feature_names=feature_names,
            threshold=float(self.threshold)
        )
        
        logger.info(f"Anomaly detection model trained: {model_id}")
        return metadata
    
    def predict(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict anomalies"""
        if self.model is None:
            raise ValueError("Model not trained")
        
        X, _ = self.feature_extractor.extract(events)
        X_scaled = self.feature_extractor.scaler.transform(X)
        
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        results = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            results.append({
                "event_id": events[i].get("id"),
                "is_anomaly": bool(pred == -1),
                "anomaly_score": float(score),
                "threshold": float(self.threshold)
            })
        
        return results
    
    def _generate_model_id(self, model_type: str, feature_set: str) -> str:
        """Generate unique model ID"""
        date_str = datetime.utcnow().strftime("%Y%m%d")
        return f"{model_type}_{feature_set}_{date_str}"


class ThreatClassificationTrainer:
    """Train threat classification models using Random Forest"""
    
    def __init__(self, feature_extractor: FeatureExtractor):
        self.feature_extractor = feature_extractor
        self.model = None
        self.label_encoder = LabelEncoder()
    
    def train(
        self,
        training_data: List[Dict[str, Any]],
        validation_split: float = 0.2,
        **kwargs
    ) -> ModelMetadata:
        """Train classification model"""
        logger.info(f"Training classification model on {len(training_data)} samples")
        
        # Extract features and labels
        X, feature_names = self.feature_extractor.extract(training_data)
        
        # Get labels
        df = pd.DataFrame(training_data)
        if 'label' not in df.columns and 'threat_type' not in df.columns:
            raise ValueError("Training data must contain 'label' or 'threat_type' column")
        
        y_raw = df.get('threat_type', df.get('label'))
        y = self.label_encoder.fit_transform(y_raw)
        
        # Scale features
        X_scaled = self.feature_extractor.scaler.fit_transform(X)
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y,
            test_size=validation_split,
            random_state=42,
            stratify=y
        )
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=kwargs.get('n_estimators', 200),
            max_depth=kwargs.get('max_depth', None),
            min_samples_split=kwargs.get('min_samples_split', 2),
            random_state=42,
            n_jobs=-1
        )
        
        train_start = datetime.utcnow()
        self.model.fit(X_train, y_train)
        training_time = (datetime.utcnow() - train_start).total_seconds()
        
        # Validate
        y_pred = self.model.predict(X_val)
        y_pred_proba = self.model.predict_proba(X_val)
        
        # Metrics
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
        
        accuracy = accuracy_score(y_val, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_val, y_pred, average='weighted'
        )
        
        # Feature importance
        feature_importance = dict(zip(
            feature_names,
            self.model.feature_importances_.tolist()
        ))
        
        metrics = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "training_time_seconds": round(training_time, 2),
            "feature_importance": feature_importance
        }
        
        # Generate model ID
        model_id = self._generate_model_id("classifier", self.feature_extractor.feature_set_name)
        
        metadata = ModelMetadata(
            model_id=model_id,
            model_type="classifier",
            feature_set=self.feature_extractor.feature_set_name,
            created_at=datetime.utcnow().isoformat(),
            training_samples=len(X_train),
            validation_samples=len(X_val),
            metrics=metrics,
            hyperparameters={
                "n_estimators": self.model.n_estimators,
                "max_depth": self.model.max_depth
            },
            feature_names=feature_names,
            classes=self.label_encoder.classes_.tolist()
        )
        
        logger.info(f"Classification model trained: {model_id}")
        return metadata
    
    def predict(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict threat classes"""
        if self.model is None:
            raise ValueError("Model not trained")
        
        X, _ = self.feature_extractor.extract(events)
        X_scaled = self.feature_extractor.scaler.transform(X)
        
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        results = []
        for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
            threat_class = self.label_encoder.inverse_transform([pred])[0]
            class_probabilities = dict(zip(
                self.label_encoder.classes_,
                proba.tolist()
            ))
            
            results.append({
                "event_id": events[i].get("id"),
                "threat_class": str(threat_class),
                "confidence": float(max(proba)),
                "class_probabilities": class_probabilities
            })
        
        return results
    
    def _generate_model_id(self, model_type: str, feature_set: str) -> str:
        """Generate unique model ID"""
        date_str = datetime.utcnow().strftime("%Y%m%d")
        return f"{model_type}_{feature_set}_{date_str}"


class ModelRegistry:
    """Manage trained models"""
    
    def __init__(self, models_dir: str = "/app/models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.loaded_models = {}  # Cache
    
    def save_model(
        self,
        trainer: Any,
        metadata: ModelMetadata
    ) -> str:
        """Save trained model and metadata"""
        model_path = self.models_dir / f"{metadata.model_id}.pkl"
        metadata_path = self.models_dir / f"{metadata.model_id}_metadata.json"
        
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': trainer.model,
                'scaler': trainer.feature_extractor.scaler,
                'label_encoders': trainer.feature_extractor.label_encoders,
                'feature_extractor': trainer.feature_extractor
            }, f)
        
        # Save metadata
        with open(metadata_path, 'w') as f:
            json.dump(asdict(metadata), f, indent=2)
        
        logger.info(f"Model saved: {model_path}")
        return str(model_path)
    
    def load_model(self, model_id: str) -> Tuple[Any, ModelMetadata]:
        """Load trained model"""
        # Check cache
        if model_id in self.loaded_models:
            return self.loaded_models[model_id]
        
        model_path = self.models_dir / f"{model_id}.pkl"
        metadata_path = self.models_dir / f"{model_id}_metadata.json"
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_id}")
        
        # Load model
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        
        # Load metadata
        with open(metadata_path, 'r') as f:
            metadata_dict = json.load(f)
            metadata = ModelMetadata(**metadata_dict)
        
        # Reconstruct trainer
        if metadata.model_type == "anomaly":
            trainer = AnomalyDetectionTrainer(model_data['feature_extractor'])
        elif metadata.model_type == "classifier":
            trainer = ThreatClassificationTrainer(model_data['feature_extractor'])
        else:
            raise ValueError(f"Unknown model type: {metadata.model_type}")
        
        trainer.model = model_data['model']
        trainer.feature_extractor.scaler = model_data['scaler']
        trainer.feature_extractor.label_encoders = model_data['label_encoders']
        
        if metadata.model_type == "anomaly":
            trainer.threshold = metadata.threshold
        elif metadata.model_type == "classifier":
            trainer.label_encoder = LabelEncoder()
            trainer.label_encoder.classes_ = np.array(metadata.classes)
        
        # Cache
        self.loaded_models[model_id] = (trainer, metadata)
        
        logger.info(f"Model loaded: {model_id}")
        return trainer, metadata
    
    def list_models(self) -> List[ModelMetadata]:
        """List all available models"""
        models = []
        
        for metadata_path in self.models_dir.glob("*_metadata.json"):
            with open(metadata_path, 'r') as f:
                metadata_dict = json.load(f)
                models.append(ModelMetadata(**metadata_dict))
        
        return models
    
    def delete_model(self, model_id: str):
        """Delete model and metadata"""
        model_path = self.models_dir / f"{model_id}.pkl"
        metadata_path = self.models_dir / f"{model_id}_metadata.json"
        
        if model_path.exists():
            model_path.unlink()
        if metadata_path.exists():
            metadata_path.unlink()
        
        # Remove from cache
        if model_id in self.loaded_models:
            del self.loaded_models[model_id]
        
        logger.info(f"Model deleted: {model_id}")
