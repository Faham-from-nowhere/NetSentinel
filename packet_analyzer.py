# packet_analyzer.py

import time
import pandas as pd
import random 
from collections import deque
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from threading import Thread, Lock
from datetime import datetime

# Configuration 
TRAINING_PACKET_COUNT = 500  # Number of packets to "learn" what is normal
MAX_PACKET_QUEUE_SIZE = 2000 # Max packets to hold in memory
ANALYSIS_WINDOW_SECONDS = 10 # Analyze traffic flows every 10 seconds

# Global State
packet_queue = deque(maxlen=MAX_PACKET_QUEUE_SIZE)
queue_lock = Lock()

model = IsolationForest(contamination=0.01) # 1% of traffic is expected to be anomalous
is_model_trained = False
last_analysis_time = time.time()

# This will hold our final anomaly data to be sent
anomaly_alerts_queue = deque()

# 1. Packet Sniffing (Scapy) 

def packet_callback(packet):
    """
    Called by Scapy for each packet sniffed.
    Adds extracted features to the global queue.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        pkt_len = packet[IP].len
        
        src_port, dst_port = 0, 0
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        features = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "pkt_len": pkt_len
        }
        
        with queue_lock:
            packet_queue.append(features)

def start_sniffing():
    """Starts the Scapy sniffer in a background thread."""
    print("[Analyzer] Starting packet sniffer...")
    # 'prn' is the callback, 'store=0' means don't store packets in memory
    t = Thread(target=lambda: sniff(prn=packet_callback, store=0), daemon=True)
    t.start()

# 2. Anomaly Detection (Scikit-learn)

def analyze_traffic():
    """
    This is the main analysis loop.
    It trains the model, then continuously analyzes traffic flows.
    """
    global is_model_trained, last_analysis_time, model
    
    print("[Analyzer] Traffic analyzer started.")
    
    while True:
        with queue_lock:
            # Copy packets for training/analysis
            current_packets = list(packet_queue)
        
        # Model Training
        if not is_model_trained:
            if len(current_packets) < TRAINING_PACKET_COUNT:
                # Not enough data to train yet
                print(f"[Analyzer] Collecting training data... {len(current_packets)}/{TRAINING_PACKET_COUNT} packets.")
                time.sleep(2)
                continue
            else:
                # Train the model on the features
                print("[Analyzer] Training Isolation Forest model...")
                df = pd.DataFrame(current_packets)
                features_to_train = df[['proto', 'src_port', 'dst_port', 'pkt_len']]
                model.fit(features_to_train)
                is_model_trained = True
                print("[Analyzer] Model training complete. Switching to detection mode.")
                
                # Clear the queue so we only detect new anomalies
                with queue_lock:
                    packet_queue.clear()
                continue
        
        # Anomaly Detection 
        current_time = time.time()
        if current_time - last_analysis_time < ANALYSIS_WINDOW_SECONDS:
            # Not time to analyze yet
            time.sleep(1)
            continue
        
        last_analysis_time = current_time
        
        packets_to_analyze = []
        with queue_lock:
            while packet_queue:
                packets_to_analyze.append(packet_queue.popleft())
        
        if not packets_to_analyze:
            # print("[Analyzer] No new packets to analyze.")
            continue
        
        df = pd.DataFrame(packets_to_analyze)
        # End Improved Logic 

        print(f"[Analyzer] Analyzing {len(df)} packets from last ~{ANALYSIS_WINDOW_SECONDS}s...")
        
        # 1. Get anomaly scores
        features_to_predict = df[['proto', 'src_port', 'dst_port', 'pkt_len']]
        scores = model.predict(features_to_predict) # Returns 1 for normal, -1 for anomaly
        
        # 2. Find the anomalies
        anomaly_indices = [i for i, score in enumerate(scores) if score == -1]
        
        if anomaly_indices:
            print(f"[Analyzer] !!! Found {len(anomaly_indices)} anomalous packets !!!")
            
            # For this hackathon, let's just grab the first anomaly in the batch
            first_anomaly_index = anomaly_indices[0]
            anomaly_packet = packets_to_analyze[first_anomaly_index] # Use the new list
            
            # 3. Format it like our mock alert 
            incident_id = f"INC-REAL-{random.randint(1000, 9999)}"
            
            # Create a simple "story"
            seq1 = {
                "timestamp": datetime.fromtimestamp(anomaly_packet['timestamp']).isoformat(),
                "type": "Unusual Packet Detected",
                "details": f"Packet from {anomaly_packet['src_ip']}:{anomaly_packet['src_port']} to {anomaly_packet['dst_ip']}:{anomaly_packet['dst_port']}"
            }
            seq2 = {
                "timestamp": datetime.fromtimestamp(anomaly_packet['timestamp']).isoformat(),
                "type": "ML Verdict",
                "details": f"Isolation Forest model flagged packet as anomaly (Score: -1)"
            }

            # This is the alert sent to the frontend
            real_alert_data = {
                "incident_id": incident_id,
                "threat_score": 95, # Anomalies from the model are always high-risk
                "main_event": "ML Anomaly Detected",
                "status": "new",
                "sequence": [seq1, seq2] # The "story"
                # The AI summary will be added in main.py
            }
            
            # Add to the queue for main.py to pick up
            anomaly_alerts_queue.append(real_alert_data)
        

def start_analysis_loop():
    """Starts the analysis loop in a background thread."""
    t = Thread(target=analyze_traffic, daemon=True)
    t.start()