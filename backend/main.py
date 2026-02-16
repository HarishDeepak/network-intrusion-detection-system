from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import subprocess
from fastapi import BackgroundTasks
import json
# Routers
from api.alerts import router as alerts_router
from api.db_endpoints import router as db_router
from api.dashboard import router as dashboard_router

# =====================================================
# FASTAPI APP SETUP
# =====================================================
app = FastAPI(title="Network Anomaly Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(alerts_router, prefix="/api")
app.include_router(db_router, prefix="/api")
app.include_router(dashboard_router, prefix="/dashboard")

# =====================================================
# CSV UPLOAD + PREDICTION + FUSION SETUP
# =====================================================
BASE_DIR = Path(__file__).resolve().parent
ATTACK_CSV_DIR = BASE_DIR / "attackcsv"
ATTACK_CSV_DIR.mkdir(parents=True, exist_ok=True)
STATUS_FILE = BASE_DIR / "pipeline_status.json"

def update_status(step: str, status: str):
    """
    step: 'prediction' or 'fusion'
    status: 'running', 'completed', 'failed'
    """
    if STATUS_FILE.exists():
        with open(STATUS_FILE, "r") as f:
            status_dict = json.load(f)
    else:
        status_dict = {}

    status_dict[step] = status

    with open(STATUS_FILE, "w") as f:
        json.dump(status_dict, f)

def run_script(script_path: Path):
    """
    Run a Python script synchronously and capture output.
    Raises RuntimeError if the script fails.
    """
    result = subprocess.run(
        ["python", str(script_path)],
        capture_output=True,
        text=True,
        cwd=BASE_DIR
    )
    if result.returncode != 0:
        raise RuntimeError(f"{script_path.name} failed:\n{result.stderr}")
    print(f"{script_path.name} finished:\n{result.stdout}")


@app.post("/upload-and-run/")
async def upload_and_run(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    if not file.filename.endswith(".csv"):
        return {"error": "Only CSV files allowed"}

    file_path = ATTACK_CSV_DIR / file.filename
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # ✅ RESET STATUS HERE
    with open(STATUS_FILE, "w") as f:
        json.dump({
            "prediction": "starting",
            "fusion": "idle"
        }, f)

    def run_pipeline():
        try:
            update_status("prediction", "running")
            run_script(BASE_DIR / "models" / "Prediction.py")
            update_status("prediction", "completed")
        except Exception as e:
            update_status("prediction", "failed")
            print("Prediction failed:", e)
            return  # ❗ STOP pipeline if prediction fails

        try:
            update_status("fusion", "running")
            run_script(BASE_DIR / "run_fusion.py")
            update_status("fusion", "completed")
        except Exception as e:
            update_status("fusion", "failed")
            print("Fusion failed:", e)

    background_tasks.add_task(run_pipeline)

    return {"message": "CSV uploaded. Processing started in background."}



@app.get("/pipeline-status/")
async def pipeline_status():
    if STATUS_FILE.exists():
        with open(STATUS_FILE, "r") as f:
            status_dict = json.load(f)
    else:
        status_dict = {"prediction": "idle", "fusion": "idle"}
    return status_dict


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
