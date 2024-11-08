from flask import Flask, jsonify, request, render_template
import tensorflow as tf
import numpy as np
import psutil
import datetime
import sqlite3
from ollama_lib import OllamaClient
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import ipaddress
import threading
import requests
import re
import os
from collections import deque
from transformers import TFAutoModel, AutoConfig
import GPUtil
from huggingface_hub import hf_hub_download
from celery import Celery

app = Flask(__name__)

# Celery-Konfiguration
def make_celery(app):
    celery = Celery(
        app.import_name,
        backend='redis://localhost:6379/0',
        broker='redis://localhost:6379/0'
    )
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

# Modell von Hugging Face laden oder herunterladen, wenn nicht vorhanden
MODEL_PATH = 'SecIDS-CNN.h5'
MODEL_ID = "Keyven/SecIDS-CNN"
FILENAME = "SecIDS-CNN.h5"

# Ersetzen Sie 'your_token_here' durch Ihren tatsächlichen Token
HF_TOKEN = "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"

# Überprüfen, ob das Modell bereits lokal vorhanden ist
if not os.path.exists(MODEL_PATH):
    print("Lade Modell von Hugging Face herunter...")
    try:
        # Herunterladen der Modell-Datei von Huggingface Hub
        model_file = hf_hub_download(repo_id=MODEL_ID, filename=FILENAME, use_auth_token=HF_TOKEN)
        # Laden des Modells mit TensorFlow/Keras
        model = tf.keras.models.load_model(model_file)
        # Speichern des Modells lokal für zukünftige Verwendungen
        model.save(MODEL_PATH)
        print("Modell erfolgreich heruntergeladen und gespeichert.")
    except Exception as e:
        print(f"Fehler beim Herunterladen des Modells: {e}")
else:
    print("Lade Modell aus lokalem Speicher...")
    model = tf.keras.models.load_model(MODEL_PATH)
    print("Modell erfolgreich aus lokalem Speicher geladen.")

# Ollama Client initialisieren
ollama_client = OllamaClient(base_url="http://localhost:11434")

# Datenbankverbindung
def get_db_connection():
    conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Initialisieren der Datenbanktabellen
def initialize_database():
    with get_db_connection() as conn:
        # Tabelle für Netzwerk-Anfragen
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                type TEXT,
                country TEXT,
                summary TEXT,
                blacklisted TEXT,
                attacks INTEGER,
                reports INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_requests_timestamp ON network_requests (timestamp);
        """)
        # Tabelle für Logs
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log TEXT
            );
        """)
        # Index für Logs
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);
        """)
        # Tabelle für Systemmetriken (falls noch nicht vorhanden)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu REAL,
                memory REAL,
                disk REAL,
                network INTEGER
            );
        """)
        # Index für Metrics
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);
        """)
        conn.commit()

# Initialisieren der Datenbank beim Start der Anwendung
initialize_database()

# Funktion zur WHOIS-Abfrage nur für IPv4-Adressen, lokale und IPv6-Adressen werden übersprungen
def get_ip_country(ip):
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return "Nicht überprüfbar"
        
        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        country = response.get("country_name", "Unbekannt")
        city = response.get("city", "Unbekannt")
        state = response.get("state", "Unbekannt")
        return f"{country}, {city}, {state}"
    except (requests.RequestException, ValueError):
        return "Fehler"

# Verwendung von deque für Netzwerk-Anfragen mit begrenzter Größe (optional, falls weiterhin verwendet)
MAX_NETWORK_REQUESTS = 1000
network_requests = deque(maxlen=MAX_NETWORK_REQUESTS)

# Funktion für System-Informationen und Hardware-Daten
@app.route('/system-info', methods=['GET'])
def system_info():
    try:
        # CPU Informationen
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'
        cpu_cores = psutil.cpu_count(logical=False)
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory().total
        disk = psutil.disk_usage('/').total

        # GPU Informationen mit GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu_usage = f"{gpus[0].load * 100:.2f}%"
            gpu_memory_used = f"{gpus[0].memoryUsed} MB"
            gpu_memory_total = f"{gpus[0].memoryTotal} MB"
        else:
            gpu_usage = "N/A"
            gpu_memory_used = "N/A"
            gpu_memory_total = "N/A"

        # Power Informationen (für Laptops)
        battery = psutil.sensors_battery()
        power_usage = battery.percent if battery else 'N/A'

        # JSON-Antwort zusammenstellen
        system_info_data = {
            "cpu_frequency": cpu_freq,
            "cpu_cores": cpu_cores,
            "cpu_usage": cpu_usage,
            "gpu_usage": gpu_usage,
            "gpu_memory_used": gpu_memory_used,
            "gpu_memory_total": gpu_memory_total,
            "power_usage": power_usage,
            "memory_total": memory,
            "disk_total": disk
        }

        # Debug-Ausgabe in der Konsole
        print("System Info:", system_info_data)

        return jsonify(system_info_data)

    except Exception as e:
        print("Fehler beim Abrufen der Systeminformationen:", e)
        return jsonify({"error": "Fehler beim Abrufen der Systeminformationen"}), 500

# CNN Modell für Netzwerkpaket-Analyse verwenden
def analyze_packet_with_cnn(packet_data):
    prediction = model.predict(np.array([packet_data]))[0]
    return "verdächtig" if prediction[1] > 0.5 else "normal"

# Celery-Aufgabe zur Analyse von Paketen
@celery.task
def analyze_packet_task(packet_data):
    prediction = model.predict(np.array([packet_data]))[0]
    return "verdächtig" if prediction[1] > 0.5 else "normal"

# Netzwerkpaket-Callback mit CNN-Modell für Sicherheitsanalyse
def packet_callback(packet):
    # Prüfen, ob das Paket TCP oder UDP über IPv4 ist
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        ip = packet[IP].src
        summary = packet.summary()

        # Überprüfen, ob die IP eine externe IPv4-Adresse ist und nicht auf der Liste der auszuschließenden IPs steht
        excluded_ips = {"144.76.114.3", "159.89.102.253"}
        if ip in excluded_ips or ipaddress.ip_address(ip).is_private or ":" in ip:
            # IP ist entweder lokal, IPv6 oder auf der Ausschlussliste
            country = "Lokal/IPv6 oder ausgeschlossen"
            is_blacklisted = False
            attacks = 0
            reports = 0
        else:
            # Externe IP-Adressen, die nicht ausgeschlossen sind, weiter prüfen
            country = get_ip_country(ip)
            print(f"IP: {ip}, Country: {country}")  # Debug-Ausgabe
            blacklist_status = check_ip_blacklist(ip)
            is_blacklisted = blacklist_status["blacklisted"]
            attacks = blacklist_status.get("attacks", 0)
            reports = blacklist_status.get("reports", 0)
        
        # Netzwerkpaket in die deque einfügen
        network_requests.append({
            "ip": ip,
            "type": "IPv4",
            "country": country,
            "summary": summary,
            "blacklisted": "Ja" if is_blacklisted else "Nein",
            "attacks": attacks,
            "reports": reports
        })

        # Netzwerkpaket in die Datenbank einfügen
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO network_requests (ip, type, country, summary, blacklisted, attacks, reports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, "IPv4", country, summary, "Ja" if is_blacklisted else "Nein", attacks, reports))
            conn.commit()

        # Log speichern
        log_message = f"Netzwerkpaket von {ip} ({country}) - Blacklisted: {is_blacklisted}"
        save_log(log_message)

        # Benachrichtigung bei Blacklist-Einträgen
        if is_blacklisted:
            notify_ai(log_message)


# Pagination und ältere Logs durchsuchen
@app.route('/logs', methods=['GET'])
def get_logs():
    page = int(request.args.get('page', 1))
    page_size = 50
    offset = (page - 1) * page_size
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        """, (page_size, offset)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])

# Logs nach bestimmten Kriterien durchsuchen
@app.route('/search-logs', methods=['POST'])
def search_logs():
    search_term = request.json.get('query', '')
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            WHERE log LIKE ? 
            ORDER BY timestamp DESC
        """, ('%' + search_term + '%',)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])

# Metriken und Logs speichern
def save_metrics(cpu, memory, disk, network):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO metrics (timestamp, cpu, memory, disk, network) 
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cpu, memory, disk, network))
        conn.commit()

def save_log(log):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO logs (timestamp, log) 
            VALUES (?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log))
        conn.commit()

# KI-Benachrichtigung bei verdächtigen Aktivitäten (kurze Antworten direkt im Prompt)
def notify_ai(message):
    short_prompt = f"{message}\nAntworte bitte kurz und prägnant, maximal 1-2 Sätze."
    response = ollama_client.generate(prompt=short_prompt)
    save_log(f"KI-Benachrichtigung: {response}")

# Systemmetriken regelmäßig analysieren
def analyze_metrics(cpu, memory, disk):
    if cpu > 85 or memory > 80 or disk > 90:
        message = f"Warnung: Hohe Systemlast - CPU: {cpu}%, RAM: {memory}%, Festplatte: {disk}%."
        notify_ai(message)

# Startseite
@app.route('/')
def home():
    return render_template('index.html')

# Server-Status
@app.route('/server-status', methods=['GET'])
def server_status():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    print(f"CPU: {cpu}, Memory: {memory}, Disk: {disk}")
    
    save_metrics(cpu, memory, disk, 0)
    analyze_metrics(cpu, memory, disk)
    
    return jsonify({
        "cpu_usage": cpu,
        "memory_usage": memory,
        "disk_usage": disk
    })

# Blocklist.de-API-Konfiguration
def check_ip_blacklist(ip):
    url = f"http://api.blocklist.de/api.php?ip={ip}&format=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return {
                "blacklisted": data.get("attacks", 0) > 0,
                "attacks": data.get("attacks", 0),
                "reports": data.get("reports", 0)
            }
        return {"blacklisted": False}
    except requests.RequestException:
        return {"blacklisted": False}

# Funktion zur Integration in Llama 3.2 für Funktion-Aufruf
def handle_blacklist_function(ip):
    result = check_ip_blacklist(ip)
    return {
        "IP": ip,
        "Blacklisted": result["blacklisted"],
        "Attacks": result["attacks"],
        "Reports": result["reports"]
    }

# IP aus Nachricht extrahieren
def extract_ip_from_message(message):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, message)
    return match.group(0) if match else None

# KI-Chat
@app.route('/chat', methods=['POST'])
def chat_with_llm():
    data = request.get_json()
    user_message = data.get('message', '')
    
    # Systemmetriken abrufen
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    context_message = (
        f"{user_message}\n"
        f"Systemmetriken: CPU: {cpu}%, Speicher: {memory}%, Festplatte: {disk}%.\n"
        "Antworte bitte kurz und prägnant."
    )
    
    tools = []
    ip_to_check = extract_ip_from_message(user_message)
    if "Blacklist-Überprüfung" in user_message and ip_to_check:
        tools = [{
            'type': 'function',
            'function': {
                'name': 'check_ip_blacklist',
                'description': 'Überprüft, ob eine IP-Adresse auf der Blacklist steht',
                'parameters': {
                    'type': 'object',
                    'properties': {
                        'ip': {'type': 'string', 'description': 'Die zu überprüfende IP-Adresse'},
                    },
                    'required': ['ip'],
                },
            }
        }]

    response = ollama_client.chat(
        model="llama3.2",
        messages=[{"role": "user", "content": context_message}],
        tools=tools
    )

    print("Llama Response:", response)
    save_log(f"Llama Response: {response}")

    if 'choices' in response and len(response['choices']) > 0:
        assistant_message = response['choices'][0]['message']['content']
    else:
        assistant_message = "Fehler: Die Antwort des LLM hat nicht das erwartete Format."

    save_log(f"Benutzer: {user_message}, KI: {assistant_message}")
    return jsonify({"response": assistant_message})

# Netzwerk-Anfragen abrufen mit Paginierung
@app.route('/network-requests', methods=['GET'])
def get_network_requests():
    try:
        page = int(request.args.get('page', 1))
        page_size = 50
        offset = (page - 1) * page_size
        with get_db_connection() as conn:
            requests = conn.execute("""
                SELECT ip, type, country, summary, blacklisted, attacks, reports, timestamp 
                FROM network_requests 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (page_size, offset)).fetchall()
        data = [dict(request) for request in requests]
        return jsonify(data)
    except Exception as e:
        print(f"Fehler beim Abrufen der Netzwerk-Anfragen: {e}")
        return jsonify({"error": "Fehler beim Abrufen der Netzwerk-Anfragen"}), 500


# Starten Sie das Paket-Sniffing in einem separaten Thread
def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True, port=5000)
