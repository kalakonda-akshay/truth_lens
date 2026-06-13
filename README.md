# TruthLens

TruthLens is an AI-powered Deepfake and Synthetic Media Verification Platform built for Cyberathon 2026. It is a production-ready hackathon prototype focused on professional UX, explainable forensic reports, and reliable local demos without custom model training.

## Stack

- Frontend: Next.js 15, React, TypeScript, Tailwind CSS
- Backend: FastAPI, SQLite
- Media analysis: OpenCV, Pillow/EXIF, Librosa, browser-safe canvas forensics
- Deployment: Vercel for frontend, Render/Railway for backend

## Features

- Cybersecurity-themed landing page
- Unified drag-and-drop upload for JPG, JPEG, PNG, WEBP, video, and audio
- Automatic image/video/audio classification and routing
- Metadata scanner with EXIF, camera, editing software, codec, and tampering indicators
- Image forensics for texture, lighting, edge, and face/finger irregularities
- Suspicious-region bounding boxes and heatmap overlays
- OpenCV frame extraction with suspicious-frame simulation
- Lip-sync forensic scoring
- Librosa-based audio clone confidence scoring
- Authenticity score, deepfake probability, and risk level
- Evidence-first results page with verdict reasons and recommendations
- Cyberathon Judge Mode with six built-in image/video/audio sample reports
- Session dashboard for total, media-type, and high-risk scan counts
- Improved PDF reports with summary, evidence, risk, and recommendations

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

Deploy `frontend/` to Vercel. It runs in standalone browser-safe prototype mode when no backend is configured. For OpenCV, EXIF, and Librosa backend analysis, set:

```bash
NEXT_PUBLIC_API_URL=https://your-backend-url
```

## Prototype Note

TruthLens does not claim legal or journalistic certainty. It produces explainable forensic signals that help users decide whether media needs expert verification.
