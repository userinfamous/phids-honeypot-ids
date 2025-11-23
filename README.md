# PHIDS - Python Honeypot Intrusion Detection System 🛡️

**A simple, vanilla, and powerful local Intrusion Detection System (IDS) with Honeypot capabilities.**

PHIDS is designed for local SOC analysis, providing a clean and "noise-free" environment to study attack patterns. It features a dual-layer detection engine and a built-in attack simulator for verification.

---

## 🎯 **Core Philosophy**

*   **Vanilla & Simple**: No complex external dependencies or cloud services. Runs locally.
*   **Noise-Free**: No unsolicited background traffic or random probes. Only real interactions and user-triggered simulations are logged.
*   **Dual-Layer Detection**: Combines real-time honeypot feedback with asynchronous IDS signature analysis.

---

## 🚀 **Key Features**

### 1. **Dual-Layer Detection Architecture**
*   **Layer 1: Honeypot Detection (Real-Time)**
    *   **HTTP Honeypot (Port 8080)**: Instantly detects SQL Injection, XSS, and Directory Traversal attempts.
    *   **SSH Honeypot (Port 2222)**: Monitors command execution and detects brute-force attempts.
*   **Layer 2: IDS Engine (Asynchronous)**
    *   Analyzes connection logs against a robust signature database to confirm threats and generate formal alerts.

### 2. **Attack Simulation**
*   Built-in **"Simulate Attack"** feature allows you to test the system's detection capabilities safely.
*   Executes **real attack payloads** (e.g., actual SQL injection strings) against the local honeypots.
*   Verifies that the dashboard and IDS engine are accurately reporting threats.

### 3. **Local SOC Dashboard**
*   **Live Feed**: Watch attacks happen in real-time via WebSocket updates.
*   **IP Tracking**: Monitor source IPs (simulated or real).
*   **Detailed Forensics**: Inspect full request bodies, headers, and SSH session commands.

---

## 🛠️ **Installation & Usage**

### **Prerequisites**
*   Python 3.8+
*   Admin/Root privileges (for binding to network ports)

### **Quick Start**

1.  **Clone the repository**
    ```bash
    git clone <repository-url>
    cd phids
    ```

2.  **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the System**
    ```bash
    # Windows (Run as Administrator)
    python main.py

    # Linux/Mac (Run with sudo)
    sudo python main.py
    ```

4.  **Access the Dashboard**
    *   Open your browser to: `http://127.0.0.1:5001`

---

## 🧪 **Testing the System**

### **Option 1: Use the Simulator**
1.  Go to the **"Attacks"** page in the dashboard.
2.  Click **"Simulate Attack"** on any scenario (e.g., SQL Injection).
3.  Watch the **Dashboard** update instantly with the detected threat.

### **Option 2: Manual Testing**
You can manually attack your local honeypots using standard tools:

*   **SSH Attack**:
    ```bash
    ssh root@127.0.0.1 -p 2222
    # Try password: 'password' (Success) or 'random' (Fail)
    ```

*   **Web Attack**:
    ```bash
    curl "http://127.0.0.1:8080/login?user=admin&pass=' OR '1'='1"
    ```

---

## 📂 **Project Structure**

*   `src/capture`: Network traffic monitoring (Scapy).
*   `src/core`: Database and logging infrastructure.
*   `src/dashboard`: Flask/FastAPI web server and UI templates.
*   `src/honeypots`: HTTP and SSH honeypot implementations.
*   `src/ids`: Intrusion Detection System engine and signatures.

---

## ⚠️ **Security Note**
This system is intended for **educational and testing purposes**. While it detects real attacks, it is a honeypot designed to be probed. Do not expose it directly to the open internet without proper isolation.
