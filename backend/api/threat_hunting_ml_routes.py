"""FastAPI Routes for Threat Hunting & ML"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import uuid

from backend.threat_hunting.query_engine import ThreatHuntingEngine
from backend.ml.training_pipeline import (
    FeatureExtractor,
    AnomalyDetectionTrainer,
    ThreatClassificationTrainer,
    ModelRegistry,
    ModelMetadata
)

logger = logging.getLogger(__name__)
from backend.api.dependencies import require_api_key

router = APIRouter(
    prefix="/edr",
    tags=["EDR Threat Hunting & ML"],
    dependencies=[Depends(require_api_key)],
)

# Global registry
model_registry = ModelRegistry()
training_jobs = {}  # In-memory job tracking


# ============================================================================
# Request/Response Models
# ============================================================================

class HuntQueryRequest(BaseModel):
    query: str = Field(..., description="EDR-QL query string")

class HuntQueryResponse(BaseModel):
    status: str
    query: str
    results: List[Dict[str, Any]]
    count: int
    execution_time_ms: float

class QueryValidationResponse(BaseModel):
    status: str
    entity_type: Optional[str] = None
    conditions_count: Optional[int] = None
    correlations_count: Optional[int] = None
    has_aggregation: Optional[bool] = None
    error: Optional[str] = None

class TrainingJobRequest(BaseModel):
    model_type: str = Field(..., description="anomaly or classifier")
    feature_set_name: str = Field(..., description="Feature set to use")
    training_data_query: str = Field(..., description="SQL query to fetch training data")
    validation_split: float = Field(0.2, ge=0.1, le=0.5)
    epochs: int = Field(10, ge=1, le=100)
    batch_size: int = Field(32, ge=8, le=256)
    hyperparameters: Optional[Dict[str, Any]] = None

class TrainingJobResponse(BaseModel):
    job_id: str
    status: str
    message: str

class PredictionRequest(BaseModel):
    model_id: str
    events: List[Dict[str, Any]]

class PredictionResponse(BaseModel):
    status: str
    model_id: str
    predictions: List[Dict[str, Any]]
    inference_time_ms: float


# ============================================================================
# Dependency: Get DB Session
# ============================================================================

def get_db_session():
    """Get database session - implement based on your DB setup"""
    # Placeholder - replace with actual DB session
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Use your actual database URL
    engine = create_engine("postgresql://user:pass@localhost/tamsilcms_edr")
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        yield session
    finally:
        session.close()


# ============================================================================
# Threat Hunting Endpoints
# ============================================================================

@router.post("/hunt", response_model=HuntQueryResponse)
async def execute_hunt_query(
    request: HuntQueryRequest,
    db = Depends(get_db_session)
):
    """
    Execute EDR-QL threat hunting query.
    
    Example query:
    ```
    HUNT process
    WHERE process_name = "powershell.exe"
      AND command_line CONTAINS "base64"
    CORRELATE network WHERE destination_port IN (443, 8080) WITHIN 5m
    TIMERANGE last 24h
    AGGREGATE count() BY endpoint_id
    OUTPUT json
    ```
    """
    try:
        engine = ThreatHuntingEngine(db)
        result = engine.hunt(request.query)
        
        if result["status"] == "error":
            raise HTTPException(status_code=400, detail=result["error"])
        
        return HuntQueryResponse(**result)
    
    except Exception as e:
        logger.error(f"Hunt query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hunt/validate", response_model=QueryValidationResponse)
async def validate_hunt_query(request: HuntQueryRequest):
    """
    Validate EDR-QL query syntax without executing.
    """
    try:
        from backend.threat_hunting.query_engine import QueryParser
        parser = QueryParser()
        result = parser.parse(request.query)
        
        return QueryValidationResponse(
            status="valid",
            entity_type=result.entity_type.value,
            conditions_count=len(result.conditions),
            correlations_count=len(result.correlations),
            has_aggregation=result.aggregation is not None
        )
    
    except Exception as e:
        return QueryValidationResponse(
            status="invalid",
            error=str(e)
        )


@router.get("/hunt/examples")
async def get_example_queries():
    """
    Get example EDR-QL queries for common hunting scenarios.
    """
    examples = [
        {
            "name": "Suspicious PowerShell",
            "description": "Detect encoded PowerShell commands with network activity",
            "query": "HUNT process WHERE process_name = 'powershell.exe' AND command_line CONTAINS 'base64' CORRELATE network WHERE destination_port IN (443, 8080) WITHIN 5m TIMERANGE last 24h AGGREGATE count() BY endpoint_id OUTPUT json"
        },
        {
            "name": "Lateral Movement",
            "description": "Detect SMB connections with suspicious tools",
            "query": "HUNT network WHERE destination_port = 445 CORRELATE process WHERE process_name IN ('psexec.exe', 'wmic.exe') WITHIN 2m TIMERANGE last 7d AGGREGATE count() BY source_ip, destination_ip HAVING count > 5 OUTPUT table"
        },
        {
            "name": "Credential Access",
            "description": "Detect credential dumping attempts",
            "query": "HUNT process WHERE (process_name CONTAINS 'mimikatz' OR command_line CONTAINS 'lsass') AND user != 'SYSTEM' TIMERANGE last 30d ORDER BY timestamp DESC LIMIT 100 OUTPUT json"
        },
        {
            "name": "Data Exfiltration",
            "description": "Detect large data uploads to external IPs",
            "query": "HUNT network WHERE upload_bytes > 10485760 AND destination_ip NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') CORRELATE file WHERE file_path CONTAINS 'archive' WITHIN 10m TIMERANGE last 24h AGGREGATE sum(upload_bytes) BY source_ip OUTPUT json"
        },
        {
            "name": "Ransomware Behavior",
            "description": "Detect mass file encryption patterns",
            "query": "HUNT file WHERE operation = 'write' AND file_extension IN ('.encrypted', '.locked', '.crypto') CORRELATE process WHERE process_name NOT IN ('System', 'svchost.exe') WITHIN 1m TIMERANGE last 1h AGGREGATE count() BY endpoint_id, process_id HAVING count > 50 OUTPUT table"
        }
    ]
    
    return {"examples": examples, "count": len(examples)}


@router.get("/hunt/entity/{entity_type}/fields")
async def get_entity_fields(entity_type: str):
    """
    Get available fields for an entity type.
    """
    entity_fields = {
        "process": [
            "process_id", "process_name", "process_image", "command_line",
            "parent_process_id", "parent_process_name", "user", "endpoint_id",
            "timestamp", "cpu_usage_percent", "memory_usage_mb"
        ],
        "network": [
            "source_ip", "destination_ip", "source_port", "destination_port",
            "protocol", "bytes_sent", "bytes_received", "process_id",
            "endpoint_id", "timestamp"
        ],
        "file": [
            "file_path", "file_name", "file_hash", "file_size_bytes",
            "operation", "process_id", "endpoint_id", "timestamp"
        ],
        "registry": [
            "registry_path", "registry_value", "operation", "process_id",
            "endpoint_id", "timestamp"
        ]
    }
    
    if entity_type not in entity_fields:
        raise HTTPException(status_code=404, detail=f"Unknown entity type: {entity_type}")
    
    return {
        "entity_type": entity_type,
        "fields": entity_fields[entity_type]
    }


# ============================================================================
# Pre-built Threat Hunting Workflows
# ============================================================================

@router.post("/hunt/workflows/apt_hunt")
async def apt_hunt_workflow(db = Depends(get_db_session)):
    """Execute APT hunting workflow"""
    queries = [
        "HUNT process WHERE process_name IN ('powershell.exe', 'cmd.exe') AND command_line CONTAINS 'base64' TIMERANGE last 24h",
        "HUNT process WHERE process_name IN ('rundll32.exe', 'regsvr32.exe') AND command_line CONTAINS '.dll' TIMERANGE last 24h",
        "HUNT network WHERE destination_port IN (4444, 8443, 9001) TIMERANGE last 24h"
    ]
    
    engine = ThreatHuntingEngine(db)
    results = []
    
    for query in queries:
        result = engine.hunt(query)
        if result["status"] == "success":
            results.extend(result["results"])
    
    return {
        "workflow": "apt_hunt",
        "results": results,
        "count": len(results)
    }


@router.post("/hunt/workflows/ransomware_hunt")
async def ransomware_hunt_workflow(db = Depends(get_db_session)):
    """Execute ransomware hunting workflow"""
    query = "HUNT file WHERE operation = 'write' AGGREGATE count() BY process_id, endpoint_id HAVING count > 50 TIMERANGE last 1h"
    
    engine = ThreatHuntingEngine(db)
    result = engine.hunt(query)
    
    return {
        "workflow": "ransomware_hunt",
        "results": result.get("results", []),
        "count": result.get("count", 0)
    }


# ============================================================================
# ML Training Endpoints
# ============================================================================

@router.post("/ml/train", response_model=TrainingJobResponse)
async def start_training_job(
    request: TrainingJobRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db_session)
):
    """
    Start ML model training job.
    
    Model types:
    - anomaly: Anomaly detection (Isolation Forest)
    - classifier: Threat classification (Random Forest)
    """
    job_id = str(uuid.uuid4())
    
    training_jobs[job_id] = {
        "status": "started",
        "model_type": request.model_type,
        "created_at": datetime.utcnow().isoformat()
    }
    
    # Run training in background
    background_tasks.add_task(
        _train_model_background,
        job_id,
        request,
        db
    )
    
    return TrainingJobResponse(
        job_id=job_id,
        status="started",
        message=f"Training job started for model type {request.model_type}"
    )


async def _train_model_background(
    job_id: str,
    request: TrainingJobRequest,
    db
):
    """Background task for model training"""
    try:
        training_jobs[job_id]["status"] = "training"
        
        # Fetch training data
        result = db.execute(request.training_data_query)
        training_data = [dict(row) for row in result.fetchall()]
        
        if len(training_data) < 100:
            raise ValueError(f"Insufficient training data: {len(training_data)} samples")
        
        # Extract features
        feature_extractor = FeatureExtractor(request.feature_set_name)
        
        # Train model
        if request.model_type == "anomaly":
            trainer = AnomalyDetectionTrainer(feature_extractor)
            metadata = trainer.train(
                training_data,
                validation_split=request.validation_split,
                **(request.hyperparameters or {})
            )
        elif request.model_type == "classifier":
            trainer = ThreatClassificationTrainer(feature_extractor)
            metadata = trainer.train(
                training_data,
                validation_split=request.validation_split,
                **(request.hyperparameters or {})
            )
        else:
            raise ValueError(f"Unknown model type: {request.model_type}")
        
        # Save model
        model_registry.save_model(trainer, metadata)
        
        training_jobs[job_id]["status"] = "completed"
        training_jobs[job_id]["model_id"] = metadata.model_id
        training_jobs[job_id]["metadata"] = metadata
        
    except Exception as e:
        logger.error(f"Training job {job_id} failed: {e}", exc_info=True)
        training_jobs[job_id]["status"] = "failed"
        training_jobs[job_id]["error"] = str(e)


@router.get("/ml/train/{job_id}/status")
async def get_training_job_status(job_id: str):
    """
    Get status of training job.
    """
    if job_id not in training_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = training_jobs[job_id]
    return {
        "job_id": job_id,
        "status": job["status"],
        "model_id": job.get("model_id"),
        "error": job.get("error")
    }


@router.get("/ml/models")
async def list_models():
    """
    List all trained models.
    """
    models = model_registry.list_models()
    
    return {
        "models": [{
            "model_id": m.model_id,
            "model_type": m.model_type,
            "feature_set": m.feature_set,
            "created_at": m.created_at,
            "metrics": m.metrics
        } for m in models],
        "count": len(models)
    }


@router.delete("/ml/models/{model_id}")
async def delete_model(model_id: str):
    """
    Delete a trained model.
    """
    try:
        model_registry.delete_model(model_id)
        return {"status": "success", "message": f"Model {model_id} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ML Inference Endpoints
# ============================================================================

@router.post("/ml/predict", response_model=PredictionResponse)
async def predict_events(request: PredictionRequest):
    """
    Run inference on events using trained model.
    """
    try:
        start_time = datetime.utcnow()
        
        # Load model
        trainer, metadata = model_registry.load_model(request.model_id)
        
        # Predict
        predictions = trainer.predict(request.events)
        
        inference_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return PredictionResponse(
            status="success",
            model_id=request.model_id,
            predictions=predictions,
            inference_time_ms=round(inference_time, 2)
        )
    
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model not found: {request.model_id}")
    except Exception as e:
        logger.error(f"Prediction failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ml/batch-predict")
async def batch_predict(
    model_id: str = Query(...),
    time_range_hours: int = Query(24, ge=1, le=168),
    db = Depends(get_db_session)
):
    """
    Run batch inference on recent events.
    """
    try:
        # Load model
        trainer, metadata = model_registry.load_model(model_id)
        
        # Fetch events
        table_name = "edr_process_events"  # Adjust based on feature set
        query = f"""
            SELECT * FROM {table_name}
            WHERE timestamp >= NOW() - INTERVAL '{time_range_hours} hours'
            LIMIT 10000
        """
        
        result = db.execute(query)
        events = [dict(row) for row in result.fetchall()]
        
        # Predict
        predictions = trainer.predict(events)
        
        # Summarize
        if metadata.model_type == "anomaly":
            anomalies = [p for p in predictions if p["is_anomaly"]]
            summary = {
                "total_events": len(predictions),
                "anomalies_detected": len(anomalies),
                "anomaly_rate": len(anomalies) / len(predictions) if predictions else 0
            }
        else:
            summary = {
                "total_events": len(predictions),
                "threat_distribution": {}
            }
        
        return {
            "status": "success",
            "model_id": model_id,
            "summary": summary,
            "predictions": predictions[:100]  # Return first 100
        }
    
    except Exception as e:
        logger.error(f"Batch prediction failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ml/features")
async def get_feature_sets():
    """
    Get available feature sets.
    """
    return {
        "feature_sets": list(FeatureExtractor.FEATURE_SETS.keys()),
        "details": FeatureExtractor.FEATURE_SETS
    }
