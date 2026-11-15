# MALGUARD AI — Malware Detection Engine Backend

Foundation microservice for static Windows Portable Executable (PE) inspection, ClamAV signature analysis, and modular Machine Learning classification. Built with Python 3.11+ and FastAPI.

---

## 1. Prerequisites & Windows Setup

### Requirements:
* **Python 3.11+** installed (verified with `python --version`)
* **PowerShell** or **Command Prompt**

### Virtual Environment Setup (Windows):

```powershell
# Navigate to the backend folder
cd backend

# Create a clean virtual environment
python -m venv venv

# Activate the virtual environment
.\venv\Scripts\Activate.ps1
# (Or in standard Command Prompt: .\venv\Scripts\activate.bat)

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 2. Configuration (`.env`)

Copy the environment template:
```powershell
cp .env.example .env
```

Key variables in `backend/.env`:
```ini
ENVIRONMENT=development
DEBUG=True

# Supabase Auth Integration
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_JWT_SECRET=

# Development demo analyst access (True allows local development with demo token)
ALLOW_DEMO_AUTH=True

# ClamAV Configuration
CLAMAV_HOST=127.0.0.1
CLAMAV_PORT=3310
CLAMAV_TIMEOUT_SEC=2.0
CLAMAV_CLI_PATH=clamscan

# Machine Learning Model Path (for future Phase 4B deployment)
ML_MODEL_PATH=app/ml/models/random_forest_v1.pkl
```

---

## 3. Running the FastAPI Server

Start the Uvicorn development server:

```powershell
cd backend
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

The server will be available at:
* **API Root & Health:** http://localhost:8000/health
* **API Documentation (Swagger UI):** http://localhost:8000/docs
* **Alternative Docs (ReDoc):** http://localhost:8000/redoc

---

## 4. Running the Automated Test Suite

Execute the full automated test suite with pytest:

```powershell
cd backend
.\venv\Scripts\python.exe -m pytest tests -v
```

All 14 integration and unit tests cover:
1. `GET /health` and `GET /api/v1/health` status checks
2. ClamAV offline / unavailable graceful fallback
3. Random Forest `model_not_loaded` validation (zero fake predictions)
4. PE header format verification (`MZ` and `PE\0\0` checks)
5. Cryptographic hash generation (SHA-256, SHA-1, MD5)
6. Shannon entropy byte calculations
7. Strict authentication requirements (`HTTPBearer`)
8. File format and 10 MB size limit enforcement
9. End-to-end binary analysis with conservative verdict synthesis

---

## 5. Endpoints Reference

### `GET /health` & `GET /api/v1/health`
Checks detection engine status and connected services.
* **Response `200 OK`**:
  ```json
  {
    "status": "online",
    "service": "MALGUARD AI — Malware Detection Engine",
    "version": "1.0.0",
    "environment": "development",
    "engines": {
      "pe_analyzer": "available (pefile static engine)",
      "clamav_daemon": "offline / unavailable",
      "random_forest_ml": "model_not_loaded (Phase 4B)"
    },
    "timestamp": "2026-11-13T12:00:00Z"
  }
  ```

### `POST /api/v1/scans`
Uploads a Windows executable (`.exe` or `.dll`, max 10 MB) for analysis.
* **Headers:** `Authorization: Bearer <supabase_jwt_or_demo_token>`
* **Body:** `multipart/form-data` with `file: <binary>`
* **Conservative Verdicts:**
  * `MALICIOUS`: Confirmed by signature match (ClamAV).
  * `SUSPICIOUS`: Flagged by validated ML model or high-risk heuristic flags.
  * `NO_THREAT_DETECTED`: When all required engines complete and find no indicators.
  * `INCONCLUSIVE`: When signature or ML engines are offline / not loaded.

