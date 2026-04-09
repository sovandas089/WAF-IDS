from fastapi import FastAPI, WebSocket, File, UploadFile, WebSocketDisconnect, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import asyncio
import os
import httpx
from starlette.background import BackgroundTask
# from backend.sniffer import PacketSniffer # Deprecated in Phase 1
from backend.analyzer import alerts_queue, analyze_request

app = FastAPI(title="WAF Dashboard API")
# sniffer = PacketSniffer() # Deprecated

# Configuration
TARGET_SERVER = "http://localhost:9000" # Dummy target backend

# Ensure temp directory exists for pcaps
os.makedirs("temp", exist_ok=True)

class AlertStreamer:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass # Connection closed

streamer = AlertStreamer()

@app.on_event("startup")
async def startup_event():
    # sniffer.start() # Deprecated
    asyncio.create_task(broadcast_alerts())

@app.on_event("shutdown")
def shutdown_event():
    # sniffer.stop() # Deprecated
    pass

async def broadcast_alerts():
    while True:
        alert = await alerts_queue.get()
        await streamer.broadcast(alert)
        alerts_queue.task_done()

# ================================
# DASHBOARD ROUTES
# ================================
@app.websocket("/dashboard/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await streamer.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        streamer.disconnect(websocket)

@app.get("/dashboard/api/rules")
async def get_rules():
    try:
        with open("backend/rules.yaml", "r") as f:
            return {"rules": f.read()}
    except Exception as e:
        return {"rules": f"Error loading rules: {str(e)}"}

from scapy.all import PcapReader, TCP, IP, Raw
from backend.analyzer import offline_analyze_request

@app.post("/dashboard/api/analyze_pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    file_path = f"temp/{file.filename}"
    with open(file_path, "wb") as f:
        f.write(await file.read())
    
    # Read and process pcap in a memory-efficient stream
    try:
        logs = []
        total_http_requests = 0
        with PcapReader(file_path) as pcap_reader:
            for packet in pcap_reader:
                if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    # Very basic HTTP request reconstruction from raw TCP stream
                    if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                        lines = payload.split("\r\n")
                        first_line = lines[0].split(" ")
                        if len(first_line) >= 2:
                            method = first_line[0]
                            path = first_line[1]
                            body_split = payload.split("\r\n\r\n", 1)
                            body = body_split[1] if len(body_split) > 1 else ""
                            ip = packet[IP].src
                            
                            log = offline_analyze_request(ip, method, path, body)
                            total_http_requests += 1

                            # To protect the browser from crashing on multi-gigabyte caps,
                            # we aggressively retain threat-logs, or up to 5000 total normal logs.
                            if log['score'] > 0 or len(logs) < 5000:
                                logs.append(log)
                        
        return {"status": "success", "message": f"Processed {total_http_requests} HTTP requests. Displaying {len(logs)} key records (filtering out excessive normal traffic).", "logs": logs[:5000]}
    except Exception as e:
        return {"status": "error", "message": f"Error parsing PCAP: {str(e)}"}
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

app.mount("/dashboard/css", StaticFiles(directory="frontend/css"), name="css")
app.mount("/dashboard/js", StaticFiles(directory="frontend/js"), name="js")

@app.get("/dashboard")
async def root():
    return FileResponse("frontend/index.html")

# ================================
# REVERSE PROXY WAF CORE
# ================================
client = httpx.AsyncClient(base_url=TARGET_SERVER)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    # Skip proxying if it's hitting the dashboard
    if path.startswith("dashboard"):
        pass

    ip = request.client.host
    method = request.method
    request_path = f"/{path}"
    
    # Read body
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8', errors='ignore')

    # WAF INSPECTION
    should_block = await analyze_request(ip, method, request_path, body_str)
    if should_block:
        return Response(content="WAF Blocked Your Request", status_code=403)

    # Forward the request to the target server mapping headers
    url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))
    rp_req = client.build_request(
        request.method, url, headers=request.headers.raw, content=body_bytes
    )

    try:
        rp_resp = await client.send(rp_req, stream=True)
        return Response(
            content=rp_resp.content,
            status_code=rp_resp.status_code,
            headers=dict(rp_resp.headers)
        )
    except httpx.ConnectError:
        return Response(content="Bad Gateway: Target backend server is down.", status_code=502)

if __name__ == "__main__":
    uvicorn.run("backend.app:app", host="0.0.0.0", port=8085, reload=True)
