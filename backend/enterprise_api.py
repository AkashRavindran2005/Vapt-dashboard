import uuid
import asyncio
import time
import logging
from typing import Dict, List, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import json
from optimized_scan import scan_single, scan_bulk

log_storage = []

class LogCapture(logging.Handler):
    
    def emit(self, record):
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            level = record.levelname
            logger_name = record.name
            message = record.getMessage()
            
            if 'optimized_scan' in logger_name:
                log_entry = f"[{timestamp}] [SCANNER-{level}] {message}"
            else:
                log_entry = f"[{timestamp}] [API-{level}] {message}"
            
            log_storage.append(log_entry)
            
            if len(log_storage) > 300:
                log_storage.pop(0)
                
        except Exception as e:
            print(f"Logging error: {e}")

log_capture_handler = LogCapture()
log_capture_handler.setLevel(logging.INFO)

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(log_capture_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

logger = logging.getLogger(__name__)

logger.info("=" * 60)
logger.info("ENTERPRISE VAPT API SERVER STARTING")
logger.info("=" * 60)
logger.info("Comprehensive logging system initialized")
logger.info("Ready to capture optimized_scan.py logs")

app = FastAPI(title="Enterprise VAPT API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info("CORS middleware configured")

_jobs: Dict[str, Dict] = {}
_bulk_jobs: Dict[str, Dict] = {}

logger.info("Job storage initialized")

class BulkScanRequest(BaseModel):
    targets: List[str]
    max_concurrent: Optional[int] = 500
    enable_exploits: Optional[bool] = False

class ScanRequest(BaseModel):
    target: str
    enable_exploits: Optional[bool] = False

def _update_bulk_progress(job_id: str, completed: int, total: int):
    if job_id in _bulk_jobs:
        _bulk_jobs[job_id]["completed"] = completed
        _bulk_jobs[job_id]["progress"] = (completed / total) * 100
        
        progress_percent = _bulk_jobs[job_id]['progress']
        logger.info(f"BULK PROGRESS | Job: {job_id[:8]}... | {completed}/{total} | {progress_percent:.1f}%")

async def _run_single_scan(job_id: str, target: str, enable_exploits: bool = False):
    
    _jobs[job_id]["status"] = "running"
    _jobs[job_id]["start_time"] = time.time()
    
    logger.info(f"SINGLE SCAN STARTED | Target: {target} | Job: {job_id[:8]}... | Exploits: {'ENABLED' if enable_exploits else 'DISABLED'}")
    
    try:
        logger.info(f"SCAN INIT | Target: {target} | Exploit mode: {'ENABLED' if enable_exploits else 'DISABLED'}")
        
        result = await scan_single(target, enable_exploits)
        
        scan_duration = time.time() - _jobs[job_id]["start_time"]
        logger.info(f"SCAN COMPLETE | Target: {target} | Duration: {scan_duration:.2f}s")
        
        if result:
            logger.info(f"RESULTS | Risk: {result.get('risk', 'Unknown')} | Vulns: {result.get('total_vulnerabilities', 0)}")
            logger.info(f"RESULTS | Ports: {len(result.get('ports_masscan', []))} | Services: {len(result.get('services', {}))}")
            
            if enable_exploits and result.get('exploit_results'):
                exploit_count = sum(len(v) for v in result['exploit_results'].values() if isinstance(v, list))
                logger.info(f"EXPLOIT RESULTS | {exploit_count} exploit tests executed")
        
        _jobs[job_id].update(
            status="finished",
            result=result,
            end_time=time.time()
        )
        
        logger.info(f"SINGLE SCAN SUCCESS | {target} | Job: {job_id[:8]}... | Duration: {scan_duration:.2f}s")
        
    except Exception as e:
        scan_duration = time.time() - _jobs[job_id]["start_time"]
        logger.error(f"SINGLE SCAN FAILED | Target: {target} | Error: {str(e)}")
        
        _jobs[job_id].update(
            status="failed",
            result={"error": str(e), "target": target, "risk": "Error"},
            end_time=time.time()
        )

async def _run_bulk_scan(job_id: str, targets: List[str], max_concurrent: int, enable_exploits: bool = False):
    
    logger.info(f"BULK SCAN STARTED | Job: {job_id[:8]}... | Targets: {len(targets)} | Exploits: {'ENABLED' if enable_exploits else 'DISABLED'}")
    
    _bulk_jobs[job_id]["status"] = "running"
    _bulk_jobs[job_id]["start_time"] = time.time()
    _bulk_jobs[job_id]["total_targets"] = len(targets)
    _bulk_jobs[job_id]["completed"] = 0
    
    try:
        logger.info(f"BULK EXEC | Starting parallel scan with {max_concurrent} concurrent workers")
        
        results = await scan_bulk(
            targets, 
            max_concurrent,
            lambda completed, total: _update_bulk_progress(job_id, completed, total),
            enable_exploits
        )
        
        scan_duration = time.time() - _bulk_jobs[job_id]["start_time"]
        logger.info(f"BULK COMPLETE | Job: {job_id[:8]}... | Duration: {scan_duration:.2f}s")
        logger.info(f"BULK RESULTS | {len(results)} targets | Avg: {scan_duration/len(targets):.2f}s per target")
        
        _bulk_jobs[job_id].update(
            status="finished",
            results=results,
            end_time=time.time()
        )
        
        logger.info(f"BULK SCAN SUCCESS | Job: {job_id[:8]}... | {len(results)} targets completed")
        
    except Exception as e:
        scan_duration = time.time() - _bulk_jobs[job_id]["start_time"]
        logger.error(f"BULK SCAN FAILED | Job: {job_id[:8]}... | Error: {str(e)}")
        
        _bulk_jobs[job_id].update(
            status="failed",
            error=str(e),
            end_time=time.time()
        )

@app.post("/api/scan")
async def enqueue_scan(tasks: BackgroundTasks, target: str = Query(...), enable_exploits: str = Query("false")):
    
    if not target.strip():
        logger.warning(f"SCAN REJECTED | Empty target")
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    
    exploit_mode = enable_exploits.lower() in ('true', '1', 'yes', 'on')
    
    job_id = str(uuid.uuid4())
    
    logger.info(f"SCAN REQUEST | Target: {target} | Job: {job_id[:8]}... | Exploits: {'ENABLED' if exploit_mode else 'DISABLED'}")
    
    _jobs[job_id] = {
        "status": "queued",
        "result": None,
        "created_time": time.time(),
        "enable_exploits": exploit_mode
    }
    
    logger.info(f"SCAN QUEUED | Job {job_id[:8]}... added to queue")
    
    tasks.add_task(_run_single_scan, job_id, target.strip(), exploit_mode)
    
    return {"job_id": job_id, "status": "queued", "exploit_mode": exploit_mode}

@app.post("/api/bulk-scan")
async def enqueue_bulk_scan(tasks: BackgroundTasks, request: BulkScanRequest):
    
    if not request.targets:
        logger.warning(f"BULK SCAN REJECTED | Empty targets")
        raise HTTPException(status_code=400, detail="Targets list cannot be empty")
    
    job_id = str(uuid.uuid4())
    
    logger.info(f"BULK SCAN REQUEST | Targets: {len(request.targets)} | Job: {job_id[:8]}... | Exploits: {'ENABLED' if request.enable_exploits else 'DISABLED'}")
    
    _bulk_jobs[job_id] = {
        "status": "queued",
        "results": None,
        "total_targets": len(request.targets),
        "completed": 0,
        "progress": 0,
        "enable_exploits": request.enable_exploits,
        "created_time": time.time()
    }
    
    logger.info(f"BULK SCAN QUEUED | Job {job_id[:8]}... added to queue")
    
    tasks.add_task(_run_bulk_scan, job_id, request.targets, request.max_concurrent or 500, request.enable_exploits)
    
    return {"job_id": job_id, "status": "queued", "exploit_mode": request.enable_exploits}

@app.get("/api/scan/{job_id}")
async def scan_status(job_id: str):
    
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job

@app.get("/api/bulk-scan/{job_id}")
async def bulk_scan_status(job_id: str):
    
    job = _bulk_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Bulk job not found")
    
    return job

@app.get("/api/stats")
async def get_stats():
    
    stats = {
        "active_jobs": len([j for j in _jobs.values() if j["status"] == "running"]),
        "active_bulk_jobs": len([j for j in _bulk_jobs.values() if j["status"] == "running"]),
        "total_jobs": len(_jobs),
        "total_bulk_jobs": len(_bulk_jobs)
    }
    
    return stats

@app.get("/api/logs")
async def get_logs():
    
    logs_copy = log_storage.copy()
    
    return {"lines": logs_copy}

@app.get("/healthz")
async def health():
    return {"status": "ok", "timestamp": time.time()}

@app.get("/")
async def root():
    return {
        "name": "Enterprise VAPT API",
        "version": "3.0.0",
        "description": "Ultra-fast vulnerability assessment with optimized_scan.py integration",
        "endpoints": {
            "scan": "/api/scan",
            "bulk_scan": "/api/bulk-scan",
            "stats": "/api/stats",
            "logs": "/api/logs (optimized_scan.py logs)",
            "health": "/healthz"
        }
    }

@app.on_event("startup")
async def startup_event():
    logger.info("SERVER STARTUP COMPLETE")
    logger.info("Ready to capture optimized_scan.py logs in frontend")
    logger.info("Exploit testing properly configured")
    logger.info("=" * 60)

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Enterprise VAPT API server...")
    logger.info("Server: http://localhost:4000")
    logger.info("Docs: http://localhost:4000/docs")
    logger.info("optimized_scan.py logs will stream to frontend")
    uvicorn.run(app, host="0.0.0.0", port=4000)
