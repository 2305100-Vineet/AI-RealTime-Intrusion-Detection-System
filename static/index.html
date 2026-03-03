import random
import time
import threading
import sqlite3
import os
import requests
import pandas as pd
import shap
import joblib
import asyncio
import secrets

from fastapi import FastAPI, Form, UploadFile, File, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

ADMIN_USER="admin"
ADMIN_PASS="soc123"
SESSION_TIMEOUT=1800

MODEL_PATH="final_binary_pipeline.pkl"
model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

# DATABASE
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

sessions={}
clients=set()

state={
    "traffic":0,
    "risk":0,
    "threat_level":"LOW",
    "events":[],
    "geo":[],
    "shap_data":[],
    "traffic_history":[]
}

def validate_session(request:Request):
    session_id=request.cookies.get("session")
    if session_id not in sessions:
        return False
    if time.time()-sessions[session_id]>SESSION_TIMEOUT:
        sessions.pop(session_id,None)
        return False
    sessions[session_id]=time.time()
    return True

def log_event(event):
    cur.execute("INSERT INTO logs VALUES (?,?,?,?)",
                (event["time"],event["status"],
                 event["risk"],event["severity"]))
    conn.commit()

def get_geo():
    try:
        r=requests.get("http://ip-api.com/json/")
        data=r.json()
        return {"lat":data["lat"],"lon":data["lon"]}
    except:
        return {"lat":random.uniform(-60,60),
                "lon":random.uniform(-180,180)}

def simulate():
    while True:
        traffic=random.randint(40,150)
        r=random.randint(1,100)

        if r>85:
            risk=random.randint(70,95)
            threat="CRITICAL"
            status="Attack"
        elif r>60:
            risk=random.randint(40,70)
            threat="HIGH"
            status="Suspicious"
        else:
            risk=random.randint(5,30)
            threat="LOW"
            status="Normal"

        geo=get_geo()

        heat_intensity=risk/100  # intensity weight

        event={
            "time":time.strftime("%H:%M:%S"),
            "status":status,
            "risk":risk,
            "severity":threat
        }

        state["traffic"]=traffic
        state["risk"]=risk
        state["threat_level"]=threat
        state["geo"].append({
            "lat":geo["lat"],
            "lon":geo["lon"],
            "intensity":heat_intensity
        })

        state["events"].insert(0,event)
        state["traffic_history"].append(traffic)

        state["events"]=state["events"][:10]
        state["traffic_history"]=state["traffic_history"][-20:]
        state["geo"]=state["geo"][-50:]

        log_event(event)
        time.sleep(15)

threading.Thread(target=simulate,daemon=True).start()

@app.get("/")
def root():
    return RedirectResponse("/static/login.html")

@app.post("/login")
def login(username: str=Form(...), password: str=Form(...)):
    if username==ADMIN_USER and password==ADMIN_PASS:
        session_id=secrets.token_hex(16)
        sessions[session_id]=time.time()
        response=RedirectResponse("/static/index.html",302)
        response.set_cookie("session",session_id)
        return response
    return RedirectResponse("/static/login.html")

@app.get("/api/data")
def data(request:Request):
    if not validate_session(request):
        return JSONResponse({"error":"Unauthorized"})
    return JSONResponse(state)

@app.websocket("/ws")
async def websocket_endpoint(websocket:WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_json(state)
    except WebSocketDisconnect:
        clients.remove(websocket)

@app.post("/api/upload")
async def upload(file:UploadFile=File(...)):
    if model is None:
        return {"error":"Model missing"}
    df=pd.read_csv(file.file)
    preds=model.predict(df)
    result="Intrusion" if sum(preds)>len(preds)/2 else "Normal"
    explainer=shap.Explainer(model)
    shap_values=explainer(df)
    state["shap_data"]=shap_values.values[0].tolist()[:5]
    return {"result":result}

@app.get("/api/report")
def report():
    path="report.pdf"
    c=canvas.Canvas(path,pagesize=letter)
    c.drawString(50,750,"AI IDS SOC Report")
    c.drawString(50,730,f"Threat: {state['threat_level']}")
    c.drawString(50,710,f"Risk: {state['risk']}%")
    c.save()
    return FileResponse(path,filename="IDS_Report.pdf")
