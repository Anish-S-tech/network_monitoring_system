from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import random
from datetime import datetime, timedelta
import threading
import time

app = Flask(__name__)
CORS(app)

# In-memory storage for demo
alerts = []
traffic_data = []
users = [
    {"id": 1, "name": "John Admin", "email": "john@company.com", "role": "admin", "status": "active", "lastLogin": "2024-01-15 10:30", "created": "2023-12-01"},
    {"id": 2, "name": "Sarah Analyst", "email": "sarah@company.com", "role": "analyst", "status": "active", "lastLogin": "2024-01-15 09:15", "created": "2023-12-15"}
]

def generate_sample_data():
    """Generate sample network data with more dynamic changes"""
    global alerts, traffic_data
    
    # Generate alerts with varying frequency
    alert_types = ["Port Scan", "DDoS Attempt", "Suspicious Login", "Malware Detected", "Unauthorized Access", "Brute Force", "SQL Injection"]
    severities = ["low", "medium", "high", "critical"]
    
    # Add new alerts randomly
    if random.random() < 0.3 and len(alerts) < 15:  # 30% chance to add alert
        alert = {
            "id": len(alerts) + 1,
            "event_type": random.choice(alert_types),
            "src_ip": f"192.168.{random.randint(1, 10)}.{random.randint(1, 255)}",
            "dst_ip": f"10.0.{random.randint(1, 5)}.{random.randint(1, 255)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": random.choice(severities),
            "status": "active"
        }
        alerts.append(alert)
    
    # Randomly resolve some alerts
    if alerts and random.random() < 0.1:  # 10% chance to resolve an alert
        alert_to_resolve = random.choice([a for a in alerts if a['status'] == 'active'])
        if alert_to_resolve:
            alert_to_resolve['status'] = 'resolved'
    
    # Generate traffic data with more variation
    base_packets = 200
    time_factor = (datetime.now().hour - 12) ** 2  # Peak around noon
    packets = base_packets + random.randint(-100, 300) + int(time_factor * 5)
    
    traffic_entry = {
        "timestamp": datetime.now().isoformat(),
        "packets": max(50, packets),  # Ensure minimum packets
        "bandwidth": random.randint(20, 150),
        "connections": random.randint(50, 300)
    }
    traffic_data.append(traffic_entry)
    
    # Keep only last 100 entries
    if len(traffic_data) > 100:
        traffic_data.pop(0)

# Background thread to generate data more frequently
def data_generator():
    while True:
        generate_sample_data()
        time.sleep(3)  # Generate data every 3 seconds

# Start background thread
threading.Thread(target=data_generator, daemon=True).start()

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    # Sort alerts by timestamp, newest first
    sorted_alerts = sorted(alerts, key=lambda x: x['timestamp'], reverse=True)
    return jsonify(sorted_alerts)

@app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    global alerts
    alerts = [a for a in alerts if a['id'] != alert_id]
    return jsonify({"message": "Alert deleted"})

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    return jsonify(traffic_data[-20:])  # Return last 20 entries

@app.route('/api/stats', methods=['GET'])
def get_stats():
    recent_traffic = traffic_data[-10:] if traffic_data else []
    active_alerts = [a for a in alerts if a['status'] == 'active']
    
    return jsonify({
        "totalPackets": sum([t['packets'] for t in recent_traffic]) * 100,  # Multiply for realistic numbers
        "avgBandwidth": sum([t['bandwidth'] for t in recent_traffic]) // len(recent_traffic) if recent_traffic else 0,
        "activeConnections": traffic_data[-1]['connections'] if traffic_data else 0,
        "alertsCount": len(active_alerts),
        "uptime": f"{99.8 + random.random() * 0.2:.1f}%"
    })

@app.route('/api/network-nodes', methods=['GET'])
def get_network_nodes():
    # Randomly change node statuses for dynamic updates
    statuses = ['online', 'warning', 'offline']
    nodes = [
        {"id": 1, "name": "Main Router", "type": "router", "ip": "192.168.1.1", "status": "online", "x": 300, "y": 50},
        {"id": 2, "name": "Web Server", "type": "server", "ip": "192.168.1.10", "status": random.choice(['online', 'warning']), "x": 150, "y": 150},
        {"id": 3, "name": "Database", "type": "server", "ip": "192.168.1.11", "status": random.choice(statuses), "x": 450, "y": 150},
        {"id": 4, "name": "Workstation 1", "type": "desktop", "ip": "192.168.1.100", "status": random.choice(['online', 'offline']), "x": 100, "y": 250},
        {"id": 5, "name": "Workstation 2", "type": "desktop", "ip": "192.168.1.101", "status": random.choice(statuses), "x": 200, "y": 250},
        {"id": 6, "name": "Mobile Device", "type": "mobile", "ip": "192.168.1.150", "status": random.choice(['online', 'warning']), "x": 400, "y": 250}
    ]
    return jsonify(nodes)

@app.route('/api/users', methods=['GET'])
def get_users():
    # Randomly update last login times
    for user in users:
        if random.random() < 0.1:  # 10% chance to update login time
            user['lastLogin'] = datetime.now().strftime("%Y-%m-%d %H:%M")
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    new_user = {
        "id": len(users) + 1,
        "name": data['name'],
        "email": data['email'],
        "role": data['role'],
        "status": data['status'],
        "lastLogin": "Never",
        "created": datetime.now().strftime("%Y-%m-%d")
    }
    users.append(new_user)
    return jsonify(new_user)

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    for user in users:
        if user['id'] == user_id:
            user.update(data)
            return jsonify(user)
    return jsonify({"error": "User not found"}), 404

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    global users
    users = [u for u in users if u['id'] != user_id]
    return jsonify({"message": "User deleted"})

@app.route('/api/reports/traffic', methods=['GET'])
def get_traffic_report():
    # Generate dynamic hourly data
    report_data = []
    for i in range(24):
        hour = (datetime.now() - timedelta(hours=23-i)).strftime("%H:00")
        base_packets = 1000
        time_multiplier = 1 + 0.5 * abs(12 - i) / 12  # Higher during business hours
        report_data.append({
            "hour": hour,
            "packets": int(base_packets * time_multiplier + random.randint(-200, 500)),
            "bandwidth": random.randint(30, 120)
        })
    return jsonify(report_data)

@app.route('/api/reports/protocols', methods=['GET'])
def get_protocol_report():
    # Slightly vary protocol distribution
    base_values = [45, 30, 15, 10]
    variations = [random.randint(-5, 5) for _ in base_values]
    values = [max(5, base + var) for base, var in zip(base_values, variations)]
    
    # Normalize to 100%
    total = sum(values)
    values = [int(v * 100 / total) for v in values]
    
    return jsonify([
        {"name": "HTTP/HTTPS", "value": values[0], "color": "#3b82f6"},
        {"name": "TCP", "value": values[1], "color": "#10b981"},
        {"name": "UDP", "value": values[2], "color": "#f59e0b"},
        {"name": "Other", "value": values[3], "color": "#ef4444"}
    ])

@app.route('/api/live-packets', methods=['GET'])
def get_live_packets():
    packets = []
    protocols = ["TCP", "UDP", "HTTP", "HTTPS", "FTP", "SSH", "DNS"]
    
    for i in range(random.randint(5, 12)):  # Variable number of packets
        packet = {
            "id": random.randint(1000, 9999),
            "source": f"192.168.{random.randint(1, 10)}.{random.randint(1, 255)}",
            "destination": f"10.0.{random.randint(1, 5)}.{random.randint(1, 255)}",
            "protocol": random.choice(protocols),
            "size": random.randint(64, 2048),
            "type": random.choice(["incoming", "outgoing"]),
            "time": datetime.now().strftime("%H:%M:%S")
        }
        packets.append(packet)
    return jsonify(packets)

if __name__ == '__main__':
    print("Starting Network Traffic Management Backend...")
    print("Server available at: http://localhost:5000")
    print("API endpoints at: http://localhost:5000/api/")
    app.run(debug=True, host='0.0.0.0', port=5000)