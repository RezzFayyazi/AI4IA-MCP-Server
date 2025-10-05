# AI4IA-MCP-Server
A Model Context Protocol Server for Role-Based Learning in AI-Assisted Cybersecurity Incident Analysis with Wazuh SIEM and OpenSearch


## 🔍 Overview

AI4IA-MCP is an intelligent Model Context Protocol (MCP) server that bridges AI assistants with Wazuh SIEM infrastructure. It provides natural language access to security alerts, vulnerability analysis, CVE databases, and network documentation through a comprehensive set of tools designed for security operations teams.

This server enables LLM assistants like Claude to perform complex security operations tasks including alert correlation, statistical analysis, vulnerability assessment, and incident investigation through conversational interfaces.


## 🏗️ Architecture

```
┌─────────────────┐
│   AI Assistant  │
│    (Claude)     │
└────────┬────────┘
         │ MCP Protocol
         │
┌────────▼────────┐
│  Wazuh AI4IA    │
│   MCP Server    │
│   (FastMCP)     │
└────────┬────────┘
         │
         ├──────────────┐
         │              │
┌────────▼────────┐ ┌──▼─────────┐
│   OpenSearch    │ │  Local     │
│    Cluster      │ │  Files     │
│  (Wazuh Data)   │ │  (CVE/PDF) │
└─────────────────┘ └────────────┘
```

## ✨ Key Features

### 🎯 Core Capabilities

- **Real-time Alert Management**: Query and filter Wazuh security alerts with flexible time ranges
- **Intelligent Alert Correlation**: Automatically discover related security events based on temporal proximity, agents, MITRE techniques, and rule patterns
- **Vulnerability Analysis**: Deep-dive into CVE vulnerabilities with CVSS scoring, categorization, and mitigation recommendations
- **Statistical Insights**: Generate comprehensive reports on alert patterns, severity distributions, and system performance
- **Agent Monitoring**: Track status and health of all Wazuh agents in your infrastructure
- **CVE Database**: Search and filter from extensive CVE datasets by severity, year, and vulnerability type
- **Network Documentation**: Parse and analyze network diagrams and PDF documentation

### 🛡️ Security Operations Use Cases

- **Incident Response**: Quickly correlate alerts to identify attack campaigns
- **Threat Hunting**: Search for specific patterns across historical security data
- **Vulnerability Management**: Prioritize patching based on detected vulnerabilities
- **Compliance Reporting**: Generate statistics for audit and compliance requirements
- **Performance Monitoring**: Track Wazuh system health and event processing metrics


## 🚀 Installation


### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the project root:

```env
OPENSEARCH_HOST=localhost:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=your_secure_password_here
```

### 4. Prepare Data Files

Place the following files in the project directory:
- `cve_data.csv` - CVE vulnerability database
- `GOAD.pdf` - Network documentation (optional)
- `NetDiagram.png` - Network diagram (optional)


## 🔧 Configuration

### OpenSearch Connection

The server connects to OpenSearch using the following indices:
- `wazuh-alerts-*` - Security alerts
- `wazuh-monitoring-*` - Agent monitoring data
- `wazuh-statistics-*` - System performance metrics
- `wazuh-states-vulnerabilities-*` - Vulnerability states

### CVE Database Format

The `cve_data.csv` should contain the following columns:
- `vulnerability.id` - CVE identifier (e.g., CVE-2024-12345)
- `vulnerability.severity` - Severity level (low, medium, high, critical)
- `vulnerability.description` - Detailed vulnerability description

## 📖 Available Tools

### 1. `get_alerts`
Retrieve Wazuh security alerts with flexible filtering.

```python
# Example usage
get_alerts(
    time_range="2h",      # Last 2 hours
    rule_level=10,        # Critical alerts only
    agent_name="server-01",
    size=100
)
```

**Parameters:**
- `time_range`: Time window (e.g., "2h", "90m", "30m") - max 6 hours
- `rule_level`: Filter by severity level (1-15)
- `agent_name`: Filter by specific agent
- `size`: Number of results to return (default: 100)

### 2. `correlate_alerts`
Find related alerts that may indicate a coordinated attack.

```python
# Example usage
correlate_alerts(
    alert_id="ABC123...",
    time_window="1h",
    max_alerts=50
)
```

**Features:**
- Temporal correlation
- Same agent detection
- Related rule groups
- Common MITRE ATT&CK techniques
- Correlation factor scoring

### 3. `get_alert_statistics`
Generate comprehensive statistical reports on alert patterns.

```python
# Example usage
get_alert_statistics(
    time_range="6h",
    agent_name="web-server",
    group="web"
)
```

**Provides:**
- Alert frequency over time
- Severity distribution
- Top alert types
- Most active agents
- MITRE technique frequency
- Rule group analysis

### 4. `analyze_vulnerability`
Deep analysis of detected vulnerabilities with CVE details.

```python
# Example usage
analyze_vulnerability(
    vulnerability_id="CVE-2024-21417",
    start_time="now-12h",
    limit=50
)
```

**Includes:**
- CVE details and descriptions
- CVSS scores and severity
- Detection timestamps
- Affected agents
- Category classification
- Mitigation suggestions

### 5. `filter_network_cves`
Search the CVE database with multiple filter criteria.

```python
# Example usage
filter_network_cves(
    severity="critical",
    year="2024",
    type="SQL Injection",
    limit=100
)
```

### 6. `get_agent_status`
Monitor the health and status of all Wazuh agents.

```python
# Example usage
get_agent_status()
```

**Returns:**
- Agent name and ID
- IP address
- Connection status
- Last keep-alive timestamp
- Wazuh version

### 7. `get_statistics`
Retrieve Wazuh system performance metrics.

```python
# Example usage
get_statistics(timeframe="3h")
```

**Metrics:**
- Events received/processed/dropped
- Events per second (EDPS)
- Queue usage percentages
- Processing efficiency
- System health indicators

### 8. `read_network_documentation`
Extract text from PDF network documentation.

```python
# Example usage
read_network_documentation(pdf_filename="GOAD.pdf")
```

### 9. `process_network_diagram`
Analyze network topology diagrams.

```python
# Example usage
process_network_diagram(
    png_filename="NetDiagram.png",
    analysis_type="detailed"
)
```

## ⚠️ Important Limitations

### Time Range Restrictions

Different tools have specific time range limitations for optimal performance:

- **`get_alerts`**: Maximum 6 hours
- **`correlate_alerts`**: Maximum 6 hours  
- **`get_alert_statistics`**: Maximum 6 hours
- **`get_statistics`**: Maximum 6 hours
- **`analyze_vulnerability`**: Maximum 12 hours

These limits prevent rate limiting and ensure responsive query performance.

## 💡 Usage Examples

### Example 1: Investigating a Security Incident

```
User: "Show me all critical alerts from the last 2 hours"
AI: [Uses get_alerts with rule_level=12+, time_range="2h"]

User: "What vulnerabilities were detected on affected systems?"
AI: [Uses analyze_vulnerability with affected agents]
```

### Example 2: Vulnerability Management

```
User: "Find all critical CVEs from 2024"
AI: [Uses filter_network_cves with severity="critical", year="2024"]

User: "Which systems are affected by CVE-2024-12345?"
AI: [Uses analyze_vulnerability with vulnerability_id]

```

### Example 3: Performance Monitoring

```
User: "How is the Wazuh system performing?"
AI: [Uses get_statistics for system metrics]

User: "Show alert trends over the last 6 hours"
AI: [Uses get_alert_statistics for trend analysis]

```



### Common Errors

**"No alerts found"**: Check time range and filter criteria  
**"CVE database not found"**: Ensure `cve_data.csv` is in the project directory  
**"Time range exceeds limit"**: Reduce time range to specified maximum  
**"Connection refused"**: Verify OpenSearch is running and accessible


## 🚀 Quick Start with Claude Desktop

### Configuration

1. **Locate your config file:**
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

2. **Add the server configuration:**
```json
{
    "mcpServers": {
        "AI4IA": {
            "command": "python",
            "args": ["/absolute/path/to/AI4IA-MCP/mcp_server.py"]
        }
    }
}
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## Acknowledgments

- [mcp-wazuh-py](https://github.com/cyberbalsa/mcp-wazuh-py) by [@cyberbalsa](https://github.com/cyberbalsa) - This project is based on and inspired by this work on Wazuh MCP integration
- [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD) by [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) — a pentesting Active Directory lab project that provides vulnerable AD environments for practicing attack techniques.  
- [Wazuh](https://wazuh.com/) - Open source security platform
- [FastMCP](https://github.com/jlowin/fastmcp) - Model Context Protocol framework
- [OpenSearch](https://opensearch.org/) - Search and analytics engine
- [Anthropic](https://www.anthropic.com/) - Claude AI assistant
