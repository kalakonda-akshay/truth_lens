# TruthLens

TruthLens is an AI-powered Deepfake and Cybersecurity Verification Platform built for Cyberathon 2026. It focuses on professional UX, explainable forensic reports, and content-derived media analysis.

## Stack

- Frontend: Next.js 15, React, TypeScript, Tailwind CSS
- Backend: FastAPI, SQLite
- Media analysis: OpenCV, Pillow/EXIF, SoundFile, NumPy FFT and cepstral forensics
- Deployment: Vercel for frontend, Render/Railway for backend

## Features

- Cybersecurity-themed landing page
- Unified dashboard for images, videos, audio, URLs, and emails
- Email/password authentication with PBKDF2 password hashing and expiring sessions
- Optional Google Identity Services login with server-side Google token verification
- User-owned cases, reports, evidence, alerts, and investigation timeline
- Working routes for every dashboard and sidebar destination
- Unified drag-and-drop upload for JPG, JPEG, PNG, WEBP, video, audio, and EML/text email files
- Automatic image/video/audio/URL/email classification and routing
- Metadata scanner with EXIF, camera, editing software, codec, and tampering indicators
- Image forensics for texture, lighting, edge, and face/finger irregularities
- Suspicious-region bounding boxes and heatmap overlays
- URL phishing detection for typosquatting, suspicious domains, credential keywords, and redirect syntax
- Email scam detection for impersonation, urgency, credential theft, attachment/link risk, and phishing language
- Audio waveform/spectrogram evidence visualization in browser-safe mode
- OpenCV frame extraction with suspicious-frame simulation
- Lip-sync forensic scoring
- Spectrogram, cepstral variance, frequency, dynamics, and pitch-pattern voice-clone scoring
- Authenticity score, deepfake probability, and risk level
- Evidence-first results page with verdict reasons and recommendations
- Cyberathon Judge Mode explaining the evidence-first workflow for real submitted evidence
- Session dashboard for total, media-type, and high-risk scan counts
- Improved PDF reports with summary, evidence, risk, and recommendations
- Official TruthLens report template with Report ID, analysis date, summary, metadata, visual analysis, AI artifact detection, evidence visualization, findings, conclusion, recommendations, disclaimer, and TEAM TRUTHLENS footer

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
NEXT_PUBLIC_BASE_PATH=
NEXT_PUBLIC_GOOGLE_CLIENT_ID=
TRUTHLENS_DATABASE_URL=sqlite:///./truthlens.db
TRUTHLENS_STORAGE_DIR=./storage
TRUTHLENS_AUTH_SECRET=replace-with-a-long-random-secret
GOOGLE_CLIENT_ID=
ALLOWED_ORIGINS=http://localhost:3000
```

## Backend Deployment

Render/Railway start command:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Set `ALLOWED_ORIGINS` to the deployed Vercel URL.

## Frontend Deployment

Deploy `frontend/` to Vercel. Image, video, and audio analysis requires the FastAPI backend; the frontend no longer generates fallback media scores. Set:

```bash
NEXT_PUBLIC_API_URL=https://your-backend-url
NEXT_PUBLIC_BASE_PATH=/TruthLens
```

For Google Sign-In, create a Google OAuth 2.0 Web Client, add the deployed frontend origin, and set the same client ID in `GOOGLE_CLIENT_ID` on the backend and `NEXT_PUBLIC_GOOGLE_CLIENT_ID` on the frontend.

The backend includes `backend/railway.json`. Use persistent storage for SQLite and forensic evidence in production.

## Prototype Note

TruthLens does not claim legal or journalistic certainty. It produces explainable forensic signals that help users decide whether media needs expert verification.
