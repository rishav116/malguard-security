# MALGUARD AI — Malware Detection & Security Intelligence Platform

MALGUARD AI is a next-generation malware analysis platform that combines static Windows PE binary inspection, Random Forest machine learning heuristics, ClamAV signature scanning, and Malix AI (Gemini-powered security assistant).

## Architecture & Technology Stack

- **Frontend**: Next.js 16 (App Router), React 19, Tailwind CSS, Framer Motion, Lucide Icons
- **Backend**: FastAPI (Python 3.14 / Uvicorn), Pydantic v2
- **Heuristic Classifier**: 69-feature Random Forest PE Classifier (`scikit-learn`)
- **Static Analysis**: `pefile` Windows PE parser (Shannon entropy, sections, suspicious imports)
- **Signature Engine**: ClamAV native daemon integration
- **Malix AI Assistant**: Real-time SSE streaming copilot (English, Hindi, Hinglish support)
- **Authentication & Database**: Supabase (PostgreSQL, Row Level Security, SSR Auth, Google OAuth)

## Project Structure

```
├── backend/                  # FastAPI microservice
│   ├── app/
│   │   ├── api/v1/          # REST endpoints (health, scans, copilot)
│   │   ├── ml/              # Feature extractor & Random Forest model
│   │   └── services/        # PE analyzer, ClamAV & Gemini services
│   └── tests/               # Pytest suite
├── src/                      # Next.js App Router frontend
│   ├── app/                 # Routes (/scanner, /copilot, /dashboard, etc.)
│   ├── components/          # Cyber UI & dashboard components
│   └── lib/api/             # Client API wrappers
├── public/                   # Static assets & custom typography
└── supabase/migrations/      # Database DDL & RLS security policies
```

## Quick Start

### 1. Frontend Development
```bash
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### 2. Backend Development
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```
API Documentation available at [http://localhost:8000/docs](http://localhost:8000/docs).

## Deployment

- **Frontend**: Deployable directly to [Vercel](https://vercel.com).
- **Backend**: Deployable to Render, Railway, Fly.io, or any VPS with Python 3.10+.
