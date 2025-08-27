# PHIDS Enhanced Dashboard Guide 🚀

**Professional log management and threat analysis capabilities for real-world network security monitoring.**

## 🎯 **New Features Overview**

Your PHIDS dashboard has been transformed from a demo tool into a professional network security monitoring interface with advanced log management, filtering, and analysis capabilities.

---

## 🗑️ **Clear Logs Functionality**

### **Purpose**
Remove test/demo data to monitor only real attack attempts against your network.

### **How to Use**
1. **Access**: Click `Controls` → `Clear Logs` in the navigation bar
2. **Choose Type**:
   - **All Logs** - Clear both connections and alerts (recommended for fresh start)
   - **Connections Only** - Keep alerts, clear honeypot connections
   - **Alerts Only** - Keep connections, clear IDS alerts
3. **Confirm**: Click "Clear Logs" to execute (irreversible action)

### **When to Use**
- **Before Production**: Clear demo data before deploying to monitor real threats
- **Regular Maintenance**: Periodic cleanup of old logs
- **Testing Cycles**: Reset between different testing scenarios
- **Demonstration Prep**: Clear old data before live demos

---

## 🔍 **Advanced Search & Filtering System**

### **Access Filters**
Click the `Filters` button in the navigation bar to reveal the filter panel.

### **Available Filters**

#### **IP Address Filter**
- **Purpose**: Find activity from specific attackers
- **Usage**: Enter full or partial IP (e.g., `192.168.1` or `192.168.1.100`)
- **Example**: Track persistent attacker behavior

#### **Service Filter**
- **Options**: All Services, SSH, HTTP
- **Purpose**: Focus on specific honeypot services
- **Usage**: Analyze attack patterns per service type

#### **Severity Filter**
- **Options**: All Severities, High, Medium, Low
- **Purpose**: Prioritize critical security events
- **Usage**: Focus on high-severity threats first

#### **Time Range Filter**
- **Options**: Last Hour, Last 24 Hours, Last Week, Custom Range
- **Purpose**: Analyze activity within specific timeframes
- **Usage**: Incident investigation and trend analysis

#### **Alert Type Filter**
- **Purpose**: Search for specific attack types
- **Examples**: "SQL Injection", "XSS", "Brute Force"
- **Usage**: Track specific threat categories

### **Filter Operations**
- **Apply**: Click "Apply" to execute filters
- **Clear**: Click "Clear" to reset all filters
- **Combine**: Use multiple filters together for precise searches

---

## 📤 **Data Export Options**

### **Export Formats**
- **CSV**: Spreadsheet-compatible format for analysis
- **JSON**: Structured data for programmatic processing

### **Export Types**

#### **Export Connections**
```
Controls → Export Connections (CSV)
```
- **Contains**: IP addresses, ports, services, timestamps, session data
- **Use Cases**: Attack pattern analysis, IP reputation research

#### **Export Alerts**
```
Controls → Export Alerts (CSV)
```
- **Contains**: Alert types, severity, descriptions, timestamps
- **Use Cases**: Incident reporting, compliance documentation

### **Filtered Exports**
- Exports respect current filter settings
- Only filtered data is included in downloads
- Useful for targeted analysis and reporting

---

## 🔄 **Live/Historical Mode Toggle**

### **Live Mode** (Default)
- **Indicator**: Blue "Live Mode" badge
- **Behavior**: Real-time updates via WebSocket
- **Use Case**: Active monitoring of ongoing attacks

### **Historical Mode**
- **Indicator**: Gray "Historical Mode" badge  
- **Behavior**: Static data analysis, no real-time updates
- **Use Case**: Forensic analysis of past incidents

### **Toggle**: Click `Controls` → `Toggle Live/Historical`

---

## 📊 **Enhanced Analytics**

### **Attack Timeline**
- **Access**: Available via API `/api/timeline`
- **Purpose**: Visualize attack patterns over time
- **Data**: Hourly breakdown of connections and unique IPs

### **Threat Summary**
- **Access**: Available via API `/api/threat-summary`
- **Purpose**: Comprehensive security overview
- **Includes**: Connection types, alert categories, severity breakdown

---

## 🎯 **Real-World Usage Scenarios**

### **Scenario 1: Production Deployment**
```bash
# 1. Clear demo data
# Use dashboard: Controls → Clear Logs → All Logs

# 2. Deploy to production network
python main.py --debug

# 3. Monitor real attacks
# Dashboard shows only genuine threats
```

### **Scenario 2: Incident Investigation**
```bash
# 1. Filter by suspicious IP
# Filters: IP Address = "192.168.1.100"

# 2. Set time range to incident window
# Filters: Time Range = Custom (incident timeframe)

# 3. Export for analysis
# Controls → Export Connections (CSV)
```

### **Scenario 3: Threat Analysis**
```bash
# 1. Filter high-severity alerts
# Filters: Severity = "High"

# 2. Focus on specific attack type
# Filters: Alert Type = "SQL Injection"

# 3. Export for reporting
# Controls → Export Alerts (CSV)
```

### **Scenario 4: Service-Specific Analysis**
```bash
# 1. Filter by service type
# Filters: Service = "SSH"

# 2. Analyze SSH-specific attacks
# Review patterns and frequencies

# 3. Compare with HTTP attacks
# Change filter to Service = "HTTP"
```

---

## 🧪 **Testing New Features**

### **Comprehensive Test**
```bash
# Run the enhanced test suite
python test_enhanced_dashboard.py

# Expected results:
# ✅ All API endpoints working
# ✅ Filtering functionality operational
# ✅ Export capabilities verified
# ✅ Analysis endpoints responding
```

### **Manual Testing Checklist**
- [ ] Clear logs modal opens and functions
- [ ] Filters panel toggles correctly
- [ ] All filter types work individually
- [ ] Combined filters produce expected results
- [ ] CSV exports download successfully
- [ ] Live/Historical mode toggle works
- [ ] Real-time updates function in Live mode
- [ ] Notifications appear for user actions

---

## 🔧 **API Endpoints Reference**

### **Log Management**
```http
POST /api/clear-logs
Body: {"type": "all|connections|alerts"}
```

### **Filtering**
```http
GET /api/filtered-connections?ip=192.168.1.100&service=ssh&limit=50
GET /api/filtered-alerts?severity=high&alert_type=SQL&limit=50
```

### **Export**
```http
GET /api/export/connections?format=csv&ip=192.168.1.100
GET /api/export/alerts?format=json&severity=high
```

### **Analytics**
```http
GET /api/timeline?hours=24
GET /api/threat-summary?hours=168
```

---

## 🎉 **Benefits for Network Security**

### **Professional Monitoring**
- **Clean Data**: Distinguish real threats from test data
- **Focused Analysis**: Filter noise to identify genuine attacks
- **Rapid Response**: Quick access to critical security events

### **Compliance & Reporting**
- **Documentation**: Export capabilities for audit trails
- **Evidence Collection**: Filtered data for incident response
- **Trend Analysis**: Historical data for security assessments

### **Operational Efficiency**
- **Time Saving**: Quick filters instead of manual log parsing
- **Automation Ready**: API endpoints for integration with SIEM systems
- **Scalable**: Handles large volumes of security data efficiently

---

**🛡️ Your PHIDS dashboard is now a professional-grade network security monitoring platform capable of real-world threat detection and analysis!**
