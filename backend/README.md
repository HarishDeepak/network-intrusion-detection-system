Network Anomaly Detection – Backend (FastAPI)

This directory contains the backend service for the Network Anomaly Detection project.

The backend is built using FastAPI and provides:

* REST APIs for dashboard and analytics data
* Server-Sent Events (SSE) for live traffic streaming
* Dummy ML logic that can later be replaced with real models

This document explains how to run the backend end-to-end using Linux or WSL.

---

## Project Structure

backend/
main.py
api/
**init**.py
stats.py
analytics.py
packets.py
models/
**init**.py
stats.py
charts.py
packet.py
services/
**init**.py
traffic.py
stream/
**init**.py
traffic.py
requirements.txt
openapi.json

---

## Prerequisites

* Linux or WSL (Ubuntu recommended)
* Python version 3.10 or higher
* Git
* Internet access to install dependencies

---

## Verify Python Installation

Run the following command:

python3 --version

Expected output example:
Python 3.10.12

---

## One-Time System Setup (WSL / Ubuntu)

Virtual environments require python3-venv, which is not installed by default.

Run this once:

sudo apt update
sudo apt install python3.10-venv

---

## Backend Setup and Run (End-to-End)

Step 1: Navigate to the backend directory

cd backend

Verify that main.py exists:

ls

Step 2: Create a Python virtual environment

python3 -m venv venv

Step 3: Activate the virtual environment

source venv/bin/activate

You should see (venv) in the terminal prompt.

Step 4: Upgrade pip (recommended)

pip install --upgrade pip

Step 5: Install backend dependencies

pip install -r requirements.txt

Step 6: Run the FastAPI server

uvicorn main:app --reload

Expected output:
Uvicorn running on [http://127.0.0.1:8000](http://127.0.0.1:8000)
Application startup complete

---

## Access API Documentation

Open a browser and go to:

[http://localhost:8000/docs](http://localhost:8000/docs)

This opens the Swagger UI, where all REST APIs can be tested.

---

## Verify REST APIs

Dashboard statistics API:

GET /api/stats

Sample response:
{
"packet_count": 1234,
"byte_count": 987654,
"detection_rate": 0.12
}

Packet list with dummy ML predictions:

GET /api/packets?count=5

Sample response:
[
{
"packet": {
"id": 1,
"src_ip": "192.168.1.10",
"dest_ip": "10.0.0.5",
"protocol": "TCP",
"length": 1200,
"timestamp": 1712345678.12
},
"prediction": {
"label": "attack",
"attack_type": "DDoS",
"confidence": 0.9
}
}
]

---

## Verify Streaming API (SSE)

Streaming endpoint:

GET /stream/traffic

Quick test in browser:
Open the following URL:

[http://localhost:8000/stream/traffic](http://localhost:8000/stream/traffic)

You should see continuously updating messages such as:

data: {"packet_rate":120,"flow_rate":45,"bytes_per_sec":32000}

JavaScript console test (recommended):
Open the browser developer console and run:

const es = new EventSource("[http://localhost:8000/stream/traffic](http://localhost:8000/stream/traffic)");
es.onmessage = e => console.log(JSON.parse(e.data));

---

## OpenAPI Contract

The backend automatically generates an OpenAPI specification at:

[http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

This file is saved as openapi.json and should be used by frontend developers as the API contract.

---

## Stopping the Server

To stop the backend server, press:

CTRL + C

---

## Common Issues and Fixes

If you see import errors:

* Ensure every backend folder contains an **init**.py file

If port 8000 is already in use:
Run the server on a different port:

uvicorn main:app --reload --port 8001

Then open:
[http://localhost:8001/docs](http://localhost:8001/docs)

---

## Notes for Collaboration

* Do not commit the venv directory
* Do not modify frontend code from the backend branch
* Do not change API response fields without coordination
* Always work on a feature branch (for example: backend-dev)

---

## Backend Status

REST APIs working
Streaming (SSE) working
Dummy ML logic integrated
Ready for frontend integration
