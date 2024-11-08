# AI-Driven Real-Time Intrusion Detection System (SecIDS)

SecIDS ist ein leistungsfähiges, KI-gestütztes Echtzeit-IDS (Intrusion Detection System), das darauf ausgelegt ist, Netzwerkpakete zu analysieren, bösartige Aktivitäten zu erkennen und proaktive Schutzmaßnahmen zu ergreifen. Dieses System kombiniert maschinelles Lernen, insbesondere ein eigens entwickeltes CNN-Modell, mit modernen Analysetechniken, um eine robuste Sicherheitslösung für Netzwerke zu bieten.

## Funktionen und Merkmale

### 1. **Real-Time Netzwerkpaket-Überwachung**
- Überwacht kontinuierlich eingehende und ausgehende Netzwerkpakete.
- Filtert Pakete nach Protokolltypen (TCP, UDP) und überprüft deren IP-Adressen.
- Nutzt spezifische Filterregeln, um lokale und IPv6-Adressen von der Analyse auszuschließen.

### 2. **IP-Blacklist-Überprüfung und KI-Benachrichtigungen**
- Prüft, ob verdächtige IP-Adressen auf einer bekannten Blacklist stehen.
- Verwendet ein AI-Tool-Calling-Feature, das nur bei spezifischen Anfragen des Benutzers ausgelöst wird, um API-Aufrufe für Blacklist-Checks zu minimieren und API-Rate-Limits effizient zu nutzen.
- Gibt dem Nutzer Echtzeit-Feedback und Benachrichtigungen über verdächtige Aktivitäten und kann sicherheitsrelevante Entscheidungen direkt treffen.

### 3. **CNN-Modell für Anomalieerkennung**
- Nutzt ein eigens entwickeltes CNN-Modell, das auf **Hugging Face** bereitgestellt ist und speziell für die Erkennung und Klassifizierung von Netzwerkbedrohungen trainiert wurde.
- Das Modell analysiert Netzwerkpaketmuster, um potenziell bösartige Aktivitäten schnell und präzise zu identifizieren.
- Unterstützung für Modell-Updates von Hugging Face, um sicherzustellen, dass immer das neueste Sicherheitswissen integriert ist.

### 4. **Automatische Datenarchivierung und Log-Management**
- Speichert Logs für eine bestimmte Zeitspanne (z. B. 10 Tage) und entfernt ältere Daten automatisch, um die Datenbank effizient zu halten.
- Ältere Logs werden in einem externen Archiv gespeichert oder automatisch gelöscht, um Speicherplatz zu sparen.
- Implementiert eine Paginierungs- und Suchfunktion für Logs, um eine effiziente Verwaltung und schnelle Analyse historischer Daten zu ermöglichen.

### 5. **Systemmetriken-Monitoring**
- Überwacht kontinuierlich CPU-, Speicher- und Festplattennutzung und gibt Warnungen bei Überlastungen aus.
- Sendet Benachrichtigungen an die KI bei hoher Systemlast, um potenziell verdächtige Aktivitäten oder Ressourcenengpässe zu erkennen.

### 6. **Web-basierte Benutzeroberfläche**
- Übersichtliche Darstellung der Netzwerk- und Systemmetriken.
- Echtzeit-Dashboard für Netzwerkaktivitäten und Blacklist-Status.
- KI-Chat-Bereich, der Benutzeranfragen für IP-Überprüfungen oder andere Aufgaben annimmt und darauf basierend automatisch Aktionen durchführt.
- Log-Management-Bereich für die Suche und Filterung von Einträgen.

### 7. **Erweiterbare Architektur**
- Flexible Integration zusätzlicher Modelle und APIs, einschließlich der Möglichkeit, neue Bedrohungsdatenquellen hinzuzufügen.
- Unterstützung für Tool-Calls über die Llama 3.2 API, die es der KI ermöglicht, externe Funktionen dynamisch aufzurufen.

## Technologie-Stack

- **Python**: Hauptprogrammiersprache
- **Flask**: Backend-Framework für die API und das Dashboard
- **SQLite**: Datenbank zur Speicherung und Verwaltung der Logs
- **TensorFlow / Keras**: Implementierung und Nutzung des CNN-Modells
- **Scapy**: Netzwerkpaket-Analyse
- **Hugging Face Model Hub**: Bereitstellung und Aktualisierung des CNN-Modells
- **Chart.js und Bootstrap**: Benutzeroberfläche für das Web-Dashboard

## Einrichtung und Installation

### 1. **Voraussetzungen**:
- Python 3.8+
- TensorFlow und Keras für das CNN-Modell
- Scapy für die Netzwerkpaket-Analyse
- Flask für die API
- Installiere Ollama - llama3.2 Model
- Zugang zur Hugging Face API (für den Zugriff auf das CNN-Modell)

### 2. **Installation**:
```bash
# Klone das Repository
git clone https://github.com/Keyvanhardani/AI-Driven-Real-Time-Intrusion-Detection-System.git
cd AI-Driven-Real-Time-Intrusion-Detection-System

# Installiere die Abhängigkeiten
pip install -r requirements.txt

Changelog:: V1.0.1
