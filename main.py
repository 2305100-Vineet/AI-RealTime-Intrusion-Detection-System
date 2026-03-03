import random
import time
import threading
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()

app.mount("/", StaticFiles(directory="static", html=True), name="static")

# ---- Global State ----
state = {
    "traffic": 0,
    "risk": 0,
    "threat_level": "LOW",
    "events": [],
    "geo": []
}

def simulate_traffic():
    while True:
        traffic = random.randint(20, 120)
        attack_chance = random.randint(1, 100)

        if attack_chance > 80:
            risk = random.randint(60, 95)
            threat = "HIGH"
            event_type = "Attack Detected"
        elif attack_chance > 50:
            risk = random.randint(30, 60)
            threat = "MEDIUM"
            event_type = "Suspicious Activity"
        else:
            risk = random.randint(5, 25)
            threat = "LOW"
            event_type = "Normal Traffic"

        geo_point = {
            "lat": random.uniform(-60, 60),
            "lon": random.uniform(-180, 180)
        }

        state["traffic"] = traffic
        state["risk"] = risk
        state["threat_level"] = threat
        state["geo"].append(geo_point)

        state["events"].insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "status": event_type,
            "risk": risk,
            "severity": threat
        })

        state["events"] = state["events"][:10]
        state["geo"] = state["geo"][-20:]

        time.sleep(15)

threading.Thread(target=simulate_traffic, daemon=True).start()

@app.get("/api/data")
def get_data():
    return JSONResponse(state)
