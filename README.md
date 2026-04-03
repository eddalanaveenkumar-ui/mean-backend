# Mean AI Backend Setup

This directory contains the Python backend for Mean AI, using FastAPI and MongoDB to handle authentication and securely store the OpenRouter API keys.

## Prerequisites

1. **Python 3.8+** installed.
2. **MongoDB** installed and running locally on standard port `27017` (or cloud MongoDB URI).

## Installation

Create a virtual environment, activate it, and install dependencies:

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Running the Server

Start the development server with:

```bash
uvicorn main:app --reload --port 8000
```
The backend will be available at `http://localhost:8000`.
You can view the interactive API docs at `http://localhost:8000/docs`.

## Integration flow with Frontend
- Form submitted: `POST /login` -> receives standard OAuth2 username(email)/password -> returns JWT token `access_token`.
- Get user details: `GET /me` (requires Authorization: Bearer <token>) -> returns if `has_api_key` is true/false.
- If no OpenRouter key linked, frontend prompts for it. Send key to: `POST /update-api-key` -> `{"api_key": "sk-or-v1-..."}`.
- To execute AI generation, frontend requests the raw key via `GET /me/api_key` temporarily into state, OR proxies requests directly through this backend.
