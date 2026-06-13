# TruthLens

TruthLens is an AI-powered Deepfake and Synthetic Media Verification Platform built for Cyberathon 2026. It is a production-ready hackathon prototype focused on professional UX, explainable forensic reports, and reliable local demos without custom model training.

## Stack

- Frontend: Next.js 15, React, TypeScript, Tailwind CSS
- Backend: FastAPI, SQLite
- Media analysis: OpenCV, Librosa, MoviePy fallback utilities
- Deployment: Vercel for frontend, Render/Railway for backend

## Features

- Cybersecurity-themed landing page
- Drag-and-drop upload dashboard for video/audio
- Metadata scanner with codec and tampering indicators
- OpenCV frame extraction with suspicious-frame simulation
- Lip-sync forensic scoring
- Librosa-based audio clone confidence scoring
- Authenticity score, deepfake probability, and risk level
- Results page with evidence, suspicious frames, awareness banner, and PDF download

## Local Development

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

## Environment

Copy `.env.example` into the matching app directories or configure these values in deployment:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
TRUTHLENS_DATABASE_URL=sqlite:///./truthlens.db
TRUTHLENS_STORAGE_DIR=./storage
ALLOWED_ORIGINS=http://localhost:3000
```

## Backend Deployment

Render/Railway start command:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Set `ALLOWED_ORIGINS` to the deployed Vercel URL.

## Frontend Deployment

Deploy `frontend/` to Vercel and set:

```bash
NEXT_PUBLIC_API_URL=https://your-backend-url
```

## Prototype Note

TruthLens does not claim legal or journalistic certainty. It produces explainable forensic signals that help users decide whether media needs expert verification.
