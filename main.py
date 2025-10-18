import uvicorn
import asyncio
import random
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# 1. Initialize FastAPI App
app = FastAPI(
    title="NetSentinel Backend",
    description="Manages packet analysis, anomaly detection, and alert streaming."
)

# 2. Data Models (Look into this Person B & C). 
# This is the Pydantic model for a single event in the timeline
class IncidentSequenceItem(BaseModel):
    timestamp: str
    type: str  # e.g., "Port Scan", "Connection Attempt", "Data Outflow"
    details: str # e.g., "Target: Device A", "Port: 3389", "Bytes: 5MB/min"

# This is the main Alert structure that will be sent
class Alert(BaseModel):
    incident_id: str
    threat_score: int # 0-100
    main_event: str  # e.g., "High-Risk Anomaly", "Potential Data Exfiltration"
    status: str # e.g., "new", "acknowledged"
    sequence: List[IncidentSequenceItem] # The "Threat Story" timeline

# 3. Mock WebSocket Endpoint
@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """
    This endpoint streams live mock alerts to the frontend.
    It sends a new alert every 5 seconds.
    """
    await websocket.accept()
    print("Frontend client connected.")
    
    try:
        while True:
            # Wait for 5 seconds
            await asyncio.sleep(5)

            # Generate Fake Alert Data 
            incident_id = f"INC-{random.randint(100, 999)}"
            score = random.randint(75, 99)
            
            fake_alert = Alert(
                incident_id=incident_id,
                threat_score=score,
                main_event="Potential Data Exfiltration",
                status="new",
                sequence=[
                    IncidentSequenceItem(
                        timestamp=datetime.now().isoformat(),
                        type="Port Scan",
                        details="Attacker 1.2.3.4 scanned ports 1-1024 on Device A."
                    ),
                    IncidentSequenceItem(
                        timestamp=datetime.now().isoformat(),
                        type="Connection Attempt",
                        details="Attacker 1.2.3.4 attempted RDP connection on port 3389."
                    ),
                    IncidentSequenceItem(
                        timestamp=datetime.now().isoformat(),
                        type="Data Outflow",
                        details="Small but steady 5MB/min outbound traffic detected."
                    )
                ]
            )
            
            # Send the alert to the frontend as JSON
            await websocket.send_json(fake_alert.model_dump())
            print(f"Sent mock alert {incident_id}")

    except WebSocketDisconnect:
        print("Frontend client disconnected.")
    except Exception as e:
        print(f"An error occurred: {e}")

# 4. (Optional) Root Endpoint for Testing
@app.get("/")
def read_root():
    return {"status": "NetSentinel Backend is running."}

# 5. Run the Server (for development)
if __name__ == "__main__":
    # This line allows to run the script directly with `python main.py`
    # Uvicorn will run the 'app' object from this file
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)