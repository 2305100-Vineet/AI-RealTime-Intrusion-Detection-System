import random
import time
import threading
import sqlite3
import os
import requests
import pandas as pd
import shap
import joblib
import secrets

from fastapi import FastAPI, Form, UploadFile, File, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = FastAPI()

# Static folder
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="static")

# ---------------- CONFIG ----------------
ADMIN_USER = "admin"
ADMIN_PASS = "soc123"
SESSION_TIMEOUT = 1800

MODEL_PATH = "final_binary_pipeline.pkl"
model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

# ---------------- DATABASE ----------------
conn = sqlite3.connect("events.db", check_same_thread=False)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS logs(
time TEXT,
status TEXT,
risk INTEGER,
severity TEXT
)
""")
conn.commit()

# ---------------- STATE ----------------
state = {
    "traffic": 0,
    "risk": 0,
    "threat_level": "LOW",
    "events": [],
    "geo": [],
    "shap_data": [],
    "traffic_history": []
}

clients = set()

# ---------------- SIMULATION ----------------

def get_geo():
    try:
        r = requests.get("http://ip-api.com/json/")
        data = r.json()
        return {"lat": data["lat"], "lon": data["lon"]}
    except:
        return {
            "lat": random.uniform(-60, 60),
            "lon": random.uniform(-180, 180)
        }

def simulate():
    while True:
        traffic = random.randint(40, 150)
        r = random.randint(1, 100)

        if r > 85:
            risk = random.randint(70, 95)
            threat = "CRITICAL"
            status = "Attack"
        elif r > 60:
            risk = random.randint(40, 70)
            threat = "HIGH"
            status = "Suspicious"
        else:
            risk = random.randint(5, 30)
            threat = "LOW"
            status = "Normal"

        geo = get_geo()
        intensity = risk / 100

        event = {
            "time": time.strftime("%H:%M:%S"),
            "status": status,
            "risk": risk,
            "severity": threat
        }

        state["traffic"] = traffic
        state["risk"] = risk
        state["threat_level"] = threat

        state["geo"].append({
            "lat": geo["lat"],
            "lon": geo["lon"],
            "intensity": intensity
        })

        state["events"].insert(0, event)
        state["traffic_history"].append(traffic)

        state["events"] = state["events"][:10]
        state["traffic_history"] = state["traffic_history"][-20:]
        state["geo"] = state["geo"][-50:]

        time.sleep(15)

threading.Thread(target=simulate, daemon=True).start()

# ---------------- ROUTES ----------------

@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        return RedirectResponse("/dashboard", status_code=302)
    return RedirectResponse("/", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/data")
def data():
    return JSONResponse(state)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_json(state)
    except WebSocketDisconnect:
        pass

@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    if model is None:
        return {"error": "Model missing"}
    df = pd.read_csv(file.file)
    preds = model.predict(df)
    result = "Intrusion" if sum(preds) > len(preds) / 2 else "Normal"
    explainer = shap.Explainer(model)
    shap_values = explainer(df)
    state["shap_data"] = shap_values.values[0].tolist()[:5]
    return {"result": result}

@app.get("/api/report")
def report():
    path = "report.pdf"
    c = canvas.Canvas(path, pagesize=letter)
    c.drawString(50, 750, "AI IDS SOC Report")
    c.drawString(50, 730, f"Threat Level: {state['threat_level']}")
    c.drawString(50, 710, f"Risk Score: {state['risk']}%")
    c.save()
    return FileResponse(path, filename="IDS_Report.pdf")
