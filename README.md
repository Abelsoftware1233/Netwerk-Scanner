# 🔭 NetScanner Pro

Netwerk reconnaissance tool — nagebouwd naar de screenshot.  
Dark hacker aesthetic, radial menu, live radar, echte netwerk scanning via Python/nmap.

---

## ⚡ Installatie & Starten

### 1. Python dependencies installeren

```bash
pip install -r requirements.txt
```

### 2. nmap installeren (aanbevolen voor volledige functionaliteit)

**Ubuntu/Debian:**
```bash
sudo apt install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**  
Download via https://nmap.org/download.html

> Zonder nmap valt de app terug op een eenvoudige Python ping-sweep.

### 3. Backend starten

```bash
python app.py
```

De server start op **http://localhost:5008**

### 4. Browser openen

Ga naar → **http://localhost:5008**

---

## 🛠 Functies

| Knop | Functie |
|------|---------|
| **▶ SCAN** | Host discovery op het netwerk (ping sweep) |
| **🔭 Scan** | Poort scan + service detectie op geselecteerde host |
| **👁 Spy** | Host info + handige terminal commando's |
| **🔌 Connect** | Verbindingsopties (SSH, RDP, HTTP, FTP) |
| **🕵 M.I.T.M.** | ARP tabel + gateway info ophalen |
| **⚡ Attack** | Aanvalsoppervlak analyse (OS detectie, open poorten) |

---

## 📁 Bestandsstructuur

```
netscanner/
├── app.py           # Flask backend (scan API)
├── index.html       # Frontend HTML
├── style.css        # Dark hacker styling
├── script.js        # Frontend logica + radar animatie
├── requirements.txt # Python packages
└── README.md
```

---

## ⚠️ Disclaimer

Gebruik **uitsluitend op netwerken die je zelf beheert** of waarvoor je expliciete toestemming hebt.  
Ongeautoriseerd netwerk scannen is **strafbaar** in Nederland en België.
