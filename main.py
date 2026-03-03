from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Header
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import joblib
import numpy as np
import sqlite3
import threading
import time
import random
import requests
from scapy.all import sniff
import secrets

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

security = HTTPBasic()

USERNAME = "admin"
PASSWORD = "soc123"

binary_pipeline = joblib.load("final_binary_pipeline.pkl")

# ==============================
# DATABASE INIT
# ==============================

def init_db():
    conn = sqlite3.connect("threat.db")
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        status TEXT,
        risk INTEGER,
        severity TEXT,
        ip TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ==============================
# LOGIN
# ==============================

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, USERNAME)
    correct_pass = secrets.compare_digest(credentials.password, PASSWORD)
    if not (correct_user and correct_pass):
        raise HTTPException(status_code=401)
    return credentials.username

@app.get("/")
def login_page():
    return FileResponse("static/login.html")

@app.get("/dashboard")
def dashboard(user: str = Depends(authenticate)):
    return FileResponse("static/index.html")

# ==============================
# LIVE IDS VARIABLES
# ==============================

packet_count = 0
total_packet_size = 0
live_mode = False
latest_result = {}
clients = []

# ==============================
# PACKET PROCESSING
# ==============================

def process_packet(packet):
    global packet_count, total_packet_size
    packet_count += 1
    total_packet_size += len(packet)

def sniff_thread():
    sniff(prn=process_packet, store=False)

threading.Thread(target=sniff_thread, daemon=True).start()

# ==============================
# THREAT INTEL API (Simulated)
# ==============================

def check_threat_intel(ip):
    # Simulated threat lookup
    return random.choice([True, False])

# ==============================
# ANALYZER LOOP (15 sec)
# ==============================

def analyzer_loop():
    global packet_count, total_packet_size, latest_result

    while True:
        time.sleep(15)

        if not live_mode:
            continue

        if packet_count == 0:
            continue

        avg_size = total_packet_size / packet_count
        features = np.zeros(40)
        features[0] = packet_count
        features[1] = avg_size

        features = features.reshape(1, -1)

        prob = binary_pipeline.predict_proba(features)[0][1]
        risk_score = int(prob * 100)
        is_attack = prob > 0.5

        severity = "Low"
        if risk_score > 70:
            severity = "High"
        elif risk_score > 40:
            severity = "Medium"

        ip = f"192.168.1.{random.randint(1,255)}"
        threat_flag = check_threat_intel(ip)

        latest_result = {
            "status": "attack" if is_attack else "safe",
            "risk_score": risk_score,
            "severity": severity,
            "ip": ip,
            "threat_intel": threat_flag
        }

        # Save to DB
        conn = sqlite3.connect("threat.db")
        c = conn.cursor()
        c.execute("INSERT INTO logs (timestamp,status,risk,severity,ip) VALUES (datetime('now'),?,?,?,?)",
                  (latest_result["status"], risk_score, severity, ip))
        conn.commit()
        conn.close()

        # reset
        packet_count = 0
        total_packet_size = 0

        # push to websocket clients
        for client in clients:
            try:
                import asyncio
                asyncio.run(client.send_json(latest_result))
            except:
                pass

threading.Thread(target=analyzer_loop, daemon=True).start()

# ==============================
# WEBSOCKET
# ==============================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.remove(websocket)

# ==============================
# TOGGLE LIVE
# ==============================

@app.post("/toggle_live")
def toggle_live():
    global live_mode
    live_mode = not live_mode
    return {"live_mode": live_mode}