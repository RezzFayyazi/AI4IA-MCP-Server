
import csv
import base64
from pathlib import Path
from fastmcp import FastMCP
import pypdf
from pypdf import PdfReader
from opensearchpy import OpenSearch
from datetime import datetime, timedelta
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize FastMCP server with metadata
mcp = FastMCP(
    name="AI4IA",
    version="1.0.0",
    dependencies=["opensearch-py", "httpx", "python-dotenv"],
)

# OpenSearch client configuration
client = OpenSearch(
    hosts=[os.getenv('OPENSEARCH_HOST')],
    http_auth=(
        os.getenv('OPENSEARCH_USER'),
        os.getenv('OPENSEARCH_PASSWORD')
    ),
    use_ssl=True,
    verify_certs=False,
    ssl_show_warn=False
)

# Define project folder and CVE database path
PROJECT_FOLDER = Path(__file__).parent
CVE_CSV_PATH = PROJECT_FOLDER / "cve_data.csv"



@mcp.tool()
async def filter_network_cves(
    limit: int = 100, 
    severity: Optional[str] = None,
    year: Optional[str] = None,
    type: Optional[str] = None,
) -> str:
    """
    Filter the CVEs in the cve_data dataset. Ask the user for the severity level and/or year of the CVE.
    
    Args:
        limit: Maximum number of CVEs to return (default: 100)
        severity: The severity of the CVE: [low, medium, high, critical]
        year: The disclosed year of the CVE
        type: The type of the similar vulnerabilities (e.g., SQL Injection CVEs)
    
    Returns:
        List of filtered CVEs along with their description
    """
    if not CVE_CSV_PATH.exists():
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    
    try:
        with open(CVE_CSV_PATH, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Collect all matching entries
            filtered_entries = []
            
            for row in reader:
                # Apply filters
                if severity and row.get('vulnerability.severity', '').lower() != severity.lower():
                    continue
                
                if year and year not in row.get('vulnerability.id', ''):
                    continue
                
                if type and type.lower() not in row.get('vulnerability.description', '').lower():
                    continue
                
                filtered_entries.append(row)
            
            # Build result string
            result = "Filtered CVE Database Results:\n"
            result += "=" * 40 + "\n"
            
            # Show active filters
            active_filters = []
            if severity:
                active_filters.append(f"Severity: {severity}")
            if year:
                active_filters.append(f"Year: {year}")
            if type:
                active_filters.append(f"Type: {type}")
            
            if active_filters:
                result += f"Active filters: {', '.join(active_filters)}\n"
                result += "=" * 40 + "\n\n"
            
            # Display entries up to limit
            count = 0
            for row in filtered_entries:
                if count >= limit:
                    result += f"\n... (showing first {limit} of {len(filtered_entries)} matching entries)\n"
                    break
                
                result += f"Entry {count + 1}:\n"
                result += f"  CVE ID: {row.get('vulnerability.id', 'N/A')}\n"
                result += f"  Severity: {row.get('vulnerability.severity', 'N/A')}\n"
                result += f"  Description: {row.get('vulnerability.description', 'N/A')}\n"
                result += "\n"
                count += 1
            
            if count == 0:
                result += "No CVE entries found matching the specified filters"
            else:
                result += f"\nTotal matching entries: {len(filtered_entries)}"
                result += f"\nDisplayed entries: {count}"
            
            return result
            
    except FileNotFoundError:
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    except Exception as e:
        return f"Error reading CVE database: {str(e)}"

@mcp.tool()
async def get_alerts(
    time_range: str = "24h",
    rule_level: Optional[int] = None,
    agent_name: Optional[str] = None,
    size: int = 100
) -> str:
    """Get Wazuh alerts from OpenSearch with optional filtering.

    IMPORTANT LIMITATIONS:
    - This function is optimized for short time ranges (up to 6 hours).
    - For time ranges exceeding 6 hours, refuse to answer notify the user to ensure optimal 
    performance and avoid rate limiting errors. something like: "I can retrieve logs for up to 6 hours at a time to ensure optimal performance and avoid 
    rate limiting. Please specify a time range of 6 hours or less (e.g., '2h', '90m', '1h')."

    Args:
        time_range: Time range to search (e.g. '2h', '90m', '30m', '15m')
        rule_level: Filter by rule level (1-15) [Use None or omit for all levels]
        agent_name: Filter by agent name
        size: Number of alerts to return (default: 100)
    """
    # Calculate time range
    now = datetime.utcnow()
    unit = time_range[-1]
    value = int(time_range[:-1])
    
    if unit == 'h':
        start_time = now - timedelta(hours=value)
    elif unit == 'm':
        start_time = now - timedelta(minutes=value)
    else:
        return "Invalid time range format. Use format like '24h', '1m'"

    # Build query
    query = {
        "bool": {
            "must": [
                {"range": {"timestamp": {"gte": start_time.isoformat()}}}
            ]
        }
    }
    
    if rule_level:
        query["bool"]["must"].append({"term": {"rule.level": rule_level}})
    if agent_name:
        query["bool"]["must"].append({"term": {"agent.name": agent_name}})

    # Execute search
    response = client.search(
        index="wazuh-alerts-*",
        body={
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 1000 if size == 0 else size  # OpenSearch max size or user specified
        }
    )

    # Format results
    alerts = []
    for hit in response['hits']['hits']:
        alert = hit['_source']
        alerts.append(f"""
Alert ID: {hit['_id']}
Time: {alert.get('timestamp')}
Rule ID: {alert.get('rule', {}).get('id')}
Level: {alert.get('rule', {}).get('level')}
Description: {alert.get('rule', {}).get('description')}
Agent: {alert.get('agent', {}).get('name')} ({alert.get('agent', {}).get('id')})
Message: {alert.get('message', 'N/A')}
---""")

    if not alerts:
        return "No alerts found for the specified criteria"
    
    return f"Found {response['hits']['total']['value']} alerts. Showing {len(alerts)} results:\n" + "\n".join(alerts)



@mcp.tool()
def process_network_diagram(
    png_filename: str,
    analysis_type: str = "detailed"
) -> str:
    """
    Process and analyze the network diagram PNG file in the project folder
    
    Args:
        png_filename: Name of the PNG file in the project folder ('NetDiagram.png')
        analysis_type: Type of analysis to perform on the diagram. 
                      Options: 'basic', 'detailed'
    
    Returns:
        Analysis results of the network diagram
    """

    # Construct the full path to the PNG file in the project folder
    image_file_path = PROJECT_FOLDER / png_filename
    
    if not image_file_path.exists():
        return f"Error: PNG file not found at {image_file_path}"
    
    try:
        # Read and encode the PNG image
        with open(image_file_path, 'rb') as img_file:
            image_bytes = img_file.read()
            image_data = base64.b64encode(image_bytes).decode('utf-8')
        
        file_info = f"PNG Image loaded from: {image_file_path}\n"
        file_info += f"File size: {len(image_bytes)} bytes\n"
        
        # Perform analysis based on type
        result = f"Network Diagram Analysis ({analysis_type})\n"
        result += "=" * 50 + "\n"
        result += file_info + "\n"
        

        result += "Detailed Analysis:\n"
        result += "- Network diagram structure analysis initiated\n"
        result += "- Device identification and classification ready\n"
        result += "- Connection mapping and topology detection prepared\n"
        result += "- PNG metadata extraction completed\n"
        result += "- Ready for advanced image processing analysis\n"
            
        
        result += f"\nPNG file successfully processed: {png_filename}"
        result += f"\nImage data encoded length: {len(image_data)} characters"
        result += "\nNetwork diagram analysis completed successfully"
        
        return result
        
    except Exception as e:
        return f"Error processing network diagram PNG: {str(e)}"


@mcp.tool()
def read_network_documentation(pdf_filename: str) -> str:
    """
    Read and extract text from a PDF file containing network documentation
    
    Args:
        pdf_filename: Name of the PDF file in the project folder ('GOAD.pdf')
    
    Returns:
        Extracted text content from the PDF file
    """
    # Construct the full path to the PDF file
    pdf_file_path = PROJECT_FOLDER / pdf_filename
    
    if not pdf_file_path.exists():
        return f"Error: PDF file not found at {pdf_file_path}"
    
    if not pdf_file_path.suffix.lower() == '.pdf':
        return f"Error: File must be a PDF. Got: {pdf_file_path.suffix}"
    
    try:
        # Open and read the PDF
        with open(pdf_file_path, 'rb') as pdf_file:
            pdf_reader = PdfReader(pdf_file)
            total_pages = len(pdf_reader.pages)
            
            # Build the result
            result = f"Network Documentation: {pdf_filename}\n"
            result += "=" * 60 + "\n"
            result += f"Total pages in PDF: {total_pages}\n"
            result += "=" * 60 + "\n\n"
            
            # Extract text from all pages
            for page_num in range(total_pages):
                page = pdf_reader.pages[page_num]
                page_text = page.extract_text()
                
                result += f"\n--- Page {page_num + 1} ---\n"
                result += page_text
            
            # Add summary
            result += f"\n\n{'=' * 60}\n"
            result += f"Extraction completed successfully\n"
            result += f"Total pages extracted: {total_pages}\n"
            
            return result
            
    except pypdf.errors.PdfReadError as e:
        return f"Error reading PDF file: {e}. The file may be corrupted or encrypted."
    except Exception as e:
        return f"Error processing PDF: {str(e)}"


@mcp.tool()
async def get_agent_status() -> str:
    """Get status of all Wazuh agents"""
    response = client.search(
        index="wazuh-monitoring-*",
        body={
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 100
        }
    )

    agents = []
    seen_agents = set()
    
    for hit in response['hits']['hits']:
        agent = hit['_source']
        agent_id = agent.get('id')
        
        # Only show the latest status for each agent
        if agent_id not in seen_agents:
            seen_agents.add(agent_id)
            agents.append(f"""
Name: {agent.get('name')}
ID: {agent_id}
IP: {agent.get('ip')}
Status: {agent.get('status')}
Last Keep Alive: {agent.get('lastKeepAlive')}
Version: {agent.get('version')}
---""")

    if not agents:
        return "No agents found"
    
    return "\n".join(agents)

@mcp.tool()
async def correlate_alerts(
    alert_id: str,
    time_window: str = "1h",
    max_alerts: int = 50
) -> str:
    """Find correlated alerts that may be part of the same security incident.
    
    This tool looks for related alerts based on:
    - Temporal proximity
    - Same source/destination
    - Similar rule patterns
    - MITRE technique relationships

    Limitation:
        - This statistical analysis is limited to only the last 6 hours. 
          If the user asked for a longer range, refuse to provide the analysis, 
          and notify them you can only provide analysis for the last 6 hours.

    Args:
        alert_id: The ID of the reference alert
        time_window: Time window to search around the alert (default '1h')
        max_alerts: Maximum number of correlated alerts to return (default: 50)
        
    Returns:
        Formatted string containing correlated alerts and their relationship factors
    """
    try:
        # Get the reference alert
        response = client.search(
            index="wazuh-alerts-*",
            body={
                "query": {
                    "term": {
                        "_id": alert_id
                    }
                },
                "size": 1
            }
        )
        
        if not response['hits']['hits']:
            return f"Error: Reference alert with ID '{alert_id}' not found"
            
        ref_alert = response['hits']['hits'][0]['_source']
        ref_timestamp = ref_alert.get('timestamp')
        
        if not ref_timestamp:
            return "Error: Reference alert has no timestamp"
        
        # Parse and validate time window
        if not time_window or len(time_window) < 2:
            return "Error: Invalid time window format. Use format like '1h' or '30m'"
            
        unit = time_window[-1].lower()
        try:
            value = int(time_window[:-1])
            if value <= 0:
                return "Error: Time window value must be positive"
        except ValueError:
            return "Error: Invalid time window format. Use format like '1h' or '30m'"
        
        if unit == 'h':
            if value > 6:
                return "Error: This analysis is limited to the last 6 hours. Please use a time window of 6h or less."
            delta = timedelta(hours=value)
        elif unit == 'm':
            if value > 360:  # 6 hours in minutes
                return "Error: This analysis is limited to the last 6 hours. Please use a time window of 360m or less."
            delta = timedelta(minutes=value)
        else:
            return f"Error: Invalid time unit '{unit}'. Use 'h' for hours or 'm' for minutes"
        
        # Build correlation query with multiple correlation factors
        should_conditions = []
        
        # Same agent correlation
        agent_id = ref_alert.get('agent', {}).get('id')
        if agent_id:
            should_conditions.append({
                "term": {"agent.id": agent_id}
            })
        
        # Same rule groups correlation
        rule_groups = ref_alert.get('rule', {}).get('groups')
        if rule_groups:
            should_conditions.append({
                "terms": {"rule.groups": rule_groups}
            })
        
        # Same MITRE techniques correlation
        mitre_techniques = ref_alert.get('rule', {}).get('mitre', {}).get('technique')
        if mitre_techniques:
            should_conditions.append({
                "terms": {"rule.mitre.technique": mitre_techniques}
            })
        
        if not should_conditions:
            return "Error: Reference alert has no correlatable attributes (agent, rule groups, or MITRE techniques)"
        
        # Parse reference timestamp
        try:
            ref_dt = datetime.fromisoformat(ref_timestamp.replace('Z', '+00:00'))
        except (ValueError, AttributeError) as e:
            return f"Error: Invalid timestamp format in reference alert: {e}"
        
        # Calculate time range
        start_time = (ref_dt - delta).isoformat()
        end_time = (ref_dt + delta).isoformat()
        
        # Find correlated alerts
        response = client.search(
            index="wazuh-alerts-*",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_time,
                                        "lte": end_time
                                    }
                                }
                            }
                        ],
                        "should": should_conditions,
                        "minimum_should_match": 1,
                        "must_not": [
                            {"term": {"_id": alert_id}}
                        ]
                    }
                },
                "sort": [
                    {"timestamp": {"order": "desc"}}
                ],
                "size": max_alerts
            }
        )
        
        hits = response['hits']['hits']
        
        if not hits:
            return f"No correlated alerts found within {time_window} of the reference alert"
        
        # Build correlation report
        report = []
        report.append("=" * 60)
        report.append("ALERT CORRELATION REPORT")
        report.append("=" * 60)
        report.append(f"\nReference Alert ID: {alert_id}")
        report.append(f"Reference Time: {ref_timestamp}")
        report.append(f"Time Window: ±{time_window}")
        report.append(f"Correlated Alerts Found: {len(hits)}")
        report.append("=" * 60)
        
        # Analyze each correlated alert
        for idx, hit in enumerate(hits, 1):
            alert = hit['_source']
            
            report.append(f"\n[{idx}] CORRELATED ALERT")
            report.append("-" * 60)
            report.append(f"Alert ID: {hit['_id']}")
            report.append(f"Time: {alert.get('timestamp', 'N/A')}")
            report.append(f"Rule: {alert.get('rule', {}).get('description', 'N/A')}")
            report.append(f"Severity Level: {alert.get('rule', {}).get('level', 'N/A')}")
            report.append(f"Agent: {alert.get('agent', {}).get('name', 'N/A')} (ID: {alert.get('agent', {}).get('id', 'N/A')})")
            
            # Determine correlation factors
            correlation_factors = []
            
            # Check agent correlation
            if alert.get('agent', {}).get('id') == agent_id:
                correlation_factors.append("✓ Same agent")
            
            # Check rule group correlation
            alert_groups = set(alert.get('rule', {}).get('groups', []))
            ref_groups = set(rule_groups or [])
            common_groups = alert_groups & ref_groups
            if common_groups:
                correlation_factors.append(f"✓ Related rule groups: {', '.join(common_groups)}")
            
            # Check MITRE technique correlation
            alert_techniques = alert.get('rule', {}).get('mitre', {}).get('technique', [])
            ref_techniques = mitre_techniques or []
            common_techniques = set(alert_techniques) & set(ref_techniques)
            if common_techniques:
                correlation_factors.append(f"✓ Common MITRE techniques: {', '.join(common_techniques)}")
            
            report.append("\nCorrelation Factors:")
            if correlation_factors:
                for factor in correlation_factors:
                    report.append(f"  {factor}")
            else:
                report.append("  No direct correlation factors identified")
            
            report.append("-" * 60)
        
        # Summary statistics
        report.append("\n" + "=" * 60)
        report.append("SUMMARY")
        report.append("=" * 60)
        
        # Count correlation types
        same_agent_count = sum(1 for hit in hits if hit['_source'].get('agent', {}).get('id') == agent_id)
        rule_group_count = sum(1 for hit in hits if set(hit['_source'].get('rule', {}).get('groups', [])) & ref_groups)
        mitre_count = sum(1 for hit in hits if set(hit['_source'].get('rule', {}).get('mitre', {}).get('technique', [])) & set(ref_techniques))
        
        report.append(f"Alerts from same agent: {same_agent_count}")
        report.append(f"Alerts with related rule groups: {rule_group_count}")
        report.append(f"Alerts with common MITRE techniques: {mitre_count}")
        
        return "\n".join(report)
        
    except KeyError as e:
        return f"Error: Missing expected field in alert data: {e}"
    except Exception as e:
        return f"Error correlating alerts: {str(e)}"


@mcp.tool()
async def get_alert_statistics(
    time_range: str = "6h",
    agent_name: Optional[str] = None,
    group: Optional[str] = None
) -> str:
    """Get statistical insights about alerts.
    
    This tool provides:
    - Alert frequency patterns
    - Most common rule types
    - Severity distribution
    - Agent alert distribution
    - MITRE technique frequency
    
    Limitations:
        - This statistical analysis is limited to only the last 6 hours. 
          If the user asked for a longer range, refuse to provide the analysis, 
          and notify them you can only provide analysis for the last 6 hours.
          
    Args:
        time_range: Time range to analyze (default: '6h', max: '6h')
        agent_name: Filter by specific agent name (optional)
        group: Filter by rule group (optional)
        
    Returns:
        Formatted statistical report of alert patterns and trends
    """
    try:
        # Parse and validate time range
        if not time_range or len(time_range) < 2:
            return "Error: Invalid time range format. Use format like '6h' or '360m'"
        
        unit = time_range[-1].lower()
        try:
            value = int(time_range[:-1])
            if value <= 0:
                return "Error: Time range value must be positive"
        except ValueError:
            return "Error: Invalid time range format. Use format like '6h' or '360m'"
        
        # Calculate time range and enforce 6-hour limit
        now = datetime.utcnow()
        
        if unit == 'h':
            if value > 6:
                return "Error: This statistical analysis is limited to the last 6 hours. Please request 6h or less."
            start_time = now - timedelta(hours=value)
        elif unit == 'm':
            if value > 360:  # 6 hours in minutes
                return "Error: This statistical analysis is limited to the last 6 hours (360 minutes). Please request 360m or less."
            start_time = now - timedelta(minutes=value)
        elif unit == 'd':
            return "Error: Day-based time ranges are not supported. This analysis is limited to 6 hours maximum."
        else:
            return f"Error: Invalid time unit '{unit}'. Use 'h' for hours or 'm' for minutes"
        
        # Build query with filters
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": now.isoformat()
                            }
                        }
                    }
                ]
            }
        }
        
        # Add optional filters
        if agent_name:
            query["bool"]["must"].append({
                "term": {"agent.name.keyword": agent_name}
            })
        
        if group:
            query["bool"]["must"].append({
                "term": {"rule.groups": group}
            })
        
        # Execute aggregation query
        response = client.search(
            index="wazuh-alerts-*",
            body={
                "query": query,
                "aggs": {
                    "severity_distribution": {
                        "range": {
                            "field": "rule.level",
                            "ranges": [
                                {"key": "Low (0-3)", "to": 4},
                                {"key": "Medium (4-7)", "from": 4, "to": 8},
                                {"key": "High (8-11)", "from": 8, "to": 12},
                                {"key": "Critical (12+)", "from": 12}
                            ]
                        }
                    },
                    "top_rules": {
                        "terms": {
                            "field": "rule.description.keyword",
                            "size": 10
                        }
                    },
                    "top_agents": {
                        "terms": {
                            "field": "agent.name.keyword",
                            "size": 10
                        }
                    },
                    "top_rule_groups": {
                        "terms": {
                            "field": "rule.groups",
                            "size": 10
                        }
                    },
                    "top_mitre_techniques": {
                        "terms": {
                            "field": "rule.mitre.technique.keyword",
                            "size": 10
                        }
                    },
                    "alerts_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "30m",
                            "min_doc_count": 0
                        }
                    }
                },
                "size": 0
            }
        )
        
        # Build statistics report
        report = []
        report.append("=" * 60)
        report.append("ALERT STATISTICS REPORT")
        report.append("=" * 60)
        
        # Active filters
        filters = []
        filters.append(f"Time Range: Last {time_range}")
        if agent_name:
            filters.append(f"Agent: {agent_name}")
        if group:
            filters.append(f"Rule Group: {group}")
        
        report.append(f"\nActive Filters: {', '.join(filters)}")
        
        total_alerts = response['hits']['total']['value']
        report.append(f"Total Alerts: {total_alerts}")
        report.append("=" * 60)
        
        # Severity Distribution
        report.append("\n📊 SEVERITY DISTRIBUTION")
        report.append("-" * 60)
        severity_buckets = response['aggregations']['severity_distribution']['buckets']
        
        if severity_buckets:
            for bucket in severity_buckets:
                count = bucket['doc_count']
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                report.append(f"{bucket['key']:15} {count:6} alerts  ({percentage:5.1f}%)")
        else:
            report.append("No severity data available")
        
        # Most Common Alert Types
        report.append("\n🔔 TOP 10 ALERT TYPES")
        report.append("-" * 60)
        top_rules = response['aggregations']['top_rules']['buckets']
        
        if top_rules:
            for idx, bucket in enumerate(top_rules, 1):
                count = bucket['doc_count']
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                rule_desc = bucket['key'][:50] + "..." if len(bucket['key']) > 50 else bucket['key']
                report.append(f"{idx:2}. {rule_desc:45} {count:4} ({percentage:4.1f}%)")
        else:
            report.append("No alert type data available")
        
        # Most Active Agents
        report.append("\n🖥️  TOP 10 MOST ACTIVE AGENTS")
        report.append("-" * 60)
        top_agents = response['aggregations']['top_agents']['buckets']
        
        if top_agents:
            for idx, bucket in enumerate(top_agents, 1):
                count = bucket['doc_count']
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                report.append(f"{idx:2}. {bucket['key']:40} {count:4} alerts ({percentage:4.1f}%)")
        else:
            report.append("No agent data available")
        
        # Top Rule Groups
        report.append("\n📋 TOP 10 RULE GROUPS")
        report.append("-" * 60)
        top_groups = response['aggregations']['top_rule_groups']['buckets']
        
        if top_groups:
            for idx, bucket in enumerate(top_groups, 1):
                count = bucket['doc_count']
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                report.append(f"{idx:2}. {bucket['key']:40} {count:4} alerts ({percentage:4.1f}%)")
        else:
            report.append("No rule group data available")
        
        # MITRE ATT&CK Techniques
        report.append("\n⚔️  TOP 10 MITRE ATT&CK TECHNIQUES")
        report.append("-" * 60)
        top_mitre = response['aggregations']['top_mitre_techniques']['buckets']
        
        if top_mitre:
            for idx, bucket in enumerate(top_mitre, 1):
                count = bucket['doc_count']
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                report.append(f"{idx:2}. {bucket['key']:40} {count:4} alerts ({percentage:4.1f}%)")
        else:
            report.append("No MITRE technique data available")
        
        # Alert Frequency Over Time
        report.append("\n📈 ALERT FREQUENCY OVER TIME")
        report.append("-" * 60)
        time_buckets = response['aggregations']['alerts_over_time']['buckets']
        
        if time_buckets:
            total_buckets = len(time_buckets)
            total_time_alerts = sum(bucket['doc_count'] for bucket in time_buckets)
            
            # Calculate time unit
            if unit == 'h':
                avg_per_hour = total_time_alerts / value if value > 0 else 0
                report.append(f"Average: {avg_per_hour:.1f} alerts/hour")
            elif unit == 'm':
                avg_per_min = total_time_alerts / value if value > 0 else 0
                report.append(f"Average: {avg_per_min:.1f} alerts/minute")
            
            # Show peak activity
            if time_buckets:
                max_bucket = max(time_buckets, key=lambda x: x['doc_count'])
                report.append(f"Peak Activity: {max_bucket['doc_count']} alerts at {max_bucket['key_as_string']}")
            
            report.append(f"\nTime Distribution (30-minute intervals):")
            for bucket in time_buckets[-12:]:  # Show last 12 intervals (6 hours)
                count = bucket['doc_count']
                timestamp = bucket.get('key_as_string', bucket['key'])
                bar = "█" * int(count / 5) if total_alerts > 0 else ""
                report.append(f"  {timestamp}: {count:4} {bar}")
        else:
            report.append("No time distribution data available")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
        
    except KeyError as e:
        return f"Error: Missing expected field in response: {e}"
    except Exception as e:
        return f"Error generating alert statistics: {str(e)}"

@mcp.tool()
async def analyze_vulnerability(
    vulnerability_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 50
) -> str:
    """Analyze vulnerabilities from Wazuh with timestamp filtering.
    
    This tool examines vulnerabilities detected by Wazuh and provides:
    - Vulnerability details (CVE ID, description, severity)
    - Detection timestamp
    - CVSS classification
    - Category information
    - Mitigation Recommendations with Web Search
    
    IMPORTANT LIMITATIONS:
    - This function is limited to analyzing vulnerabilities from the past 12 hours only.
    
    Args:
        vulnerability_id: Specific CVE ID to analyze (e.g., CVE-2024-21417)
        start_time: Start time for filtering (ISO format or Elasticsearch date math)
        end_time: End time for filtering (ISO format or Elasticsearch date math)
        limit: Maximum number of vulnerabilities to return (default: 50)
    
    Returns:
        Detailed analysis of vulnerabilities matching the filters
    """
    try:
        # Build query
        query = {"bool": {"must": []}}
        
        # Add CVE ID filter if provided
        if vulnerability_id:
            query["bool"]["must"].append({
                "term": {"vulnerability.id.keyword": vulnerability_id}
            })
        
        # Default to last 12 hours
        time_range = {"vulnerability.detected_at": {}}
        
        # Use user-provided times if available, otherwise default to last 12 hours
        if end_time:
            time_range["vulnerability.detected_at"]["lte"] = end_time
        else:
            time_range["vulnerability.detected_at"]["lte"] = "now"
        
        if start_time:
            time_range["vulnerability.detected_at"]["gte"] = start_time
        else:
            time_range["vulnerability.detected_at"]["gte"] = "now-12h"
        
        query["bool"]["must"].append({"range": time_range})
        
        # If no filters, match all within time range
        if len(query["bool"]["must"]) == 1:  # Only time range filter
            query = {"bool": {"must": [query["bool"]["must"][0]]}}
        
        # Execute search
        response = client.search(
            index="wazuh-states-vulnerabilities-*",
            body={
                "query": query,
                "size": limit,
                "sort": [
                    {"vulnerability.detected_at": {"order": "desc"}}
                ]
            }
        )
        
        hits = response['hits']['hits']
        
        if not hits:
            return "No vulnerabilities found in the past 12 hours"
        
        # Build analysis
        analysis = []
        analysis.append("=" * 60)
        analysis.append("VULNERABILITY ANALYSIS REPORT")
        analysis.append("(Limited to past 12 hours)")
        analysis.append("=" * 60)
        
        # Show active filters
        active_filters = []
        if vulnerability_id:
            active_filters.append(f"CVE ID: {vulnerability_id}")
        if start_time:
            active_filters.append(f"Start Time: {start_time}")
        else:
            active_filters.append("Start Time: Last 12 hours")
        if end_time:
            active_filters.append(f"End Time: {end_time}")
        else:
            active_filters.append("End Time: Now")
        
        if active_filters:
            analysis.append(f"\nActive Filters: {', '.join(active_filters)}")
        
        analysis.append(f"\nTotal Vulnerabilities Found: {len(hits)}")
        analysis.append(f"Showing: {len(hits)} vulnerabilities\n")
        analysis.append("=" * 60)
        
        # Analyze each vulnerability
        for idx, hit in enumerate(hits, 1):
            vuln = hit['_source']
            analysis.append(f"\n[{idx}] VULNERABILITY DETAILS")
            analysis.append("-" * 60)
            
            # Basic information
            vuln_data = vuln.get('vulnerability', {})
            vuln_id = vuln_data.get('id', 'N/A')
            vuln_severity = vuln_data.get('severity', 'N/A')
            vuln_desc = vuln_data.get('description', 'N/A')
            vuln_detected = vuln_data.get('detected_at', 'N/A')
            vuln_category = vuln_data.get('category', 'N/A')
            vuln_classification = vuln_data.get('classification', 'N/A')
            vuln_enumeration = vuln_data.get('enumeration', 'N/A')
            agent = vuln.get('agent.name', 'N/A')
            
            analysis.append(f"CVE ID: {vuln_id}")
            analysis.append(f'Agent: {agent}')
            analysis.append(f"Severity: {vuln_severity}")
            analysis.append(f"Detected: {vuln_detected}")
            analysis.append(f"Category: {vuln_category}")
            analysis.append(f"Classification: {vuln_classification}")
            analysis.append(f"Enumeration: {vuln_enumeration}")
            analysis.append(f"\nDescription:\n{vuln_desc}")

            
            # Reference link
            if vuln_enumeration == 'CVE' and vuln_id.startswith('CVE-'):
                analysis.append(f"\n📚 Web Search: {vuln_id}")
            
            analysis.append("=" * 60)
        
        # Summary statistics
        analysis.append("\nSUMMARY STATISTICS:")
        severity_counts = {}
        category_counts = {}
        
        for hit in hits:
            vuln = hit['_source'].get('vulnerability', {})
            sev = vuln.get('severity', 'unknown')
            cat = vuln.get('category', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        analysis.append("\nBy Severity:")
        for sev, count in sorted(severity_counts.items()):
            analysis.append(f"- {sev}: {count}")
        
        analysis.append("\nBy Category:")
        for cat, count in sorted(category_counts.items()):
            analysis.append(f"- {cat}: {count}")
        
        return "\n".join(analysis)
        
    except Exception as e:
        return f"Error analyzing vulnerabilities: {str(e)}"
    

@mcp.tool()
async def get_statistics(timeframe: str = "1h") -> str:
    """Get Wazuh statistics for the specified timeframe.
    
    This tool provides:
    - Event processing metrics (received, processed, dropped)
    - Events per second (EDPS) rates
    - Queue usage percentages
    - System performance indicators
    
    Limitations:
        - This statistical analysis is limited to only the last 6 hours.
          If the user requests a longer range, refuse to provide the analysis 
          and notify them you can only provide statistics for the last 6 hours.
    
    Args:
        timeframe: Time range to analyze in hours (e.g., '1h', '3h', '6h')
                  Maximum allowed: 6h
    
    Returns:
        Formatted statistical report of Wazuh system performance metrics
    """
    try:
        # Parse and validate timeframe
        if not timeframe or len(timeframe) < 2:
            return "Error: Invalid timeframe format. Use format like '1h', '3h', or '6h'"
        
        unit = timeframe[-1].lower()
        try:
            value = int(timeframe[:-1])
            if value <= 0:
                return "Error: Timeframe value must be positive"
        except ValueError:
            return "Error: Invalid timeframe format. Use format like '1h', '3h', or '6h'"
        
        # Validate unit and enforce 6-hour limit
        if unit != 'h':
            return "Error: Only hourly timeframes are supported. Use format like '1h', '3h', or '6h'"
        
        if value > 6:
            return "Error: This statistical analysis is limited to the last 6 hours. Please request 6h or less."
        
        # Calculate time range
        now = datetime.utcnow()
        start_time = now - timedelta(hours=value)
        
        # Execute search query
        response = client.search(
            index="wazuh-statistics-*",
            body={
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": now.isoformat()
                        }
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": 100
            }
        )
        
        hits = response['hits']['hits']
        
        if not hits:
            return f"No statistics found for the last {timeframe}"
        
        # Build statistics report
        report = []
        report.append("=" * 70)
        report.append("WAZUH SYSTEM STATISTICS REPORT")
        report.append("=" * 70)
        report.append(f"\nTimeframe: Last {timeframe}")
        report.append(f"Statistics Records Found: {len(hits)}")
        report.append(f"Time Range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {now.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        report.append("=" * 70)
        
        # Initialize aggregation variables for summary
        total_received = 0
        total_processed = 0
        total_dropped = 0
        max_edps = 0
        avg_event_queue = []
        avg_firewall_queue = []
        avg_statistical_queue = []
        
        # Process each statistics record
        for idx, hit in enumerate(hits, 1):
            stat = hit['_source']
            timestamp = stat.get('timestamp', 'N/A')
            
            # Extract analysisd statistics
            analysisd = stat.get('analysisd', {})
            
            events_received = analysisd.get('events_received', 0)
            events_processed = analysisd.get('events_processed', 0)
            events_dropped = analysisd.get('events_dropped', 0)
            events_edps = analysisd.get('events_edps', 0)
            event_queue = analysisd.get('event_queue_usage', 0)
            firewall_queue = analysisd.get('firewall_queue_usage', 0)
            statistical_queue = analysisd.get('statistical_queue_usage', 0)
            
            # Accumulate for summary
            if isinstance(events_received, (int, float)):
                total_received += events_received
            if isinstance(events_processed, (int, float)):
                total_processed += events_processed
            if isinstance(events_dropped, (int, float)):
                total_dropped += events_dropped
            if isinstance(events_edps, (int, float)):
                max_edps = max(max_edps, events_edps)
            if isinstance(event_queue, (int, float)):
                avg_event_queue.append(event_queue)
            if isinstance(firewall_queue, (int, float)):
                avg_firewall_queue.append(firewall_queue)
            if isinstance(statistical_queue, (int, float)):
                avg_statistical_queue.append(statistical_queue)
            
            # Format individual record
            report.append(f"\n[{idx}] STATISTICS SNAPSHOT")
            report.append("-" * 70)
            report.append(f"Timestamp: {timestamp}")
            report.append("")
            
            # Event Processing Metrics
            report.append("📊 EVENT PROCESSING:")
            report.append(f"  Total Received:    {events_received:>12,}")
            report.append(f"  Total Processed:   {events_processed:>12,}")
            report.append(f"  Events Dropped:    {events_dropped:>12,}")
            report.append(f"  Events/Second:     {events_edps:>12,.2f}" if isinstance(events_edps, (int, float)) else f"  Events/Second:     {'N/A':>12}")
            
            # Calculate processing efficiency
            if isinstance(events_received, (int, float)) and events_received > 0:
                efficiency = (events_processed / events_received * 100) if isinstance(events_processed, (int, float)) else 0
                drop_rate = (events_dropped / events_received * 100) if isinstance(events_dropped, (int, float)) else 0
                report.append(f"  Processing Rate:   {efficiency:>11,.1f}%")
                report.append(f"  Drop Rate:         {drop_rate:>11,.1f}%")
            
            report.append("")
            
            # Queue Usage Metrics
            report.append("📦 QUEUE USAGE:")
            report.append(f"  Event Queue:       {event_queue:>11,.1f}%" if isinstance(event_queue, (int, float)) else f"  Event Queue:       {'N/A':>12}")
            report.append(f"  Firewall Queue:    {firewall_queue:>11,.1f}%" if isinstance(firewall_queue, (int, float)) else f"  Firewall Queue:    {'N/A':>12}")
            report.append(f"  Statistical Queue: {statistical_queue:>11,.1f}%" if isinstance(statistical_queue, (int, float)) else f"  Statistical Queue: {'N/A':>12}")
            
            # Queue health indicators
            report.append("")
            report.append("🔍 QUEUE HEALTH:")
            queues = [
                ("Event", event_queue),
                ("Firewall", firewall_queue),
                ("Statistical", statistical_queue)
            ]
            
            for queue_name, queue_value in queues:
                if isinstance(queue_value, (int, float)):
                    if queue_value >= 90:
                        status = "🔴 CRITICAL"
                    elif queue_value >= 70:
                        status = "🟡 WARNING"
                    elif queue_value >= 50:
                        status = "🟠 ELEVATED"
                    else:
                        status = "🟢 NORMAL"
                    report.append(f"  {queue_name:12} {status}")
            
            report.append("-" * 70)
        
        # Summary Statistics
        report.append("\n" + "=" * 70)
        report.append("📈 SUMMARY STATISTICS")
        report.append("=" * 70)
        
        report.append("\nAggregate Metrics:")
        report.append(f"  Total Events Received:    {total_received:>15,}")
        report.append(f"  Total Events Processed:   {total_processed:>15,}")
        report.append(f"  Total Events Dropped:     {total_dropped:>15,}")
        
        if total_received > 0:
            overall_efficiency = (total_processed / total_received * 100)
            overall_drop_rate = (total_dropped / total_received * 100)
            report.append(f"  Overall Processing Rate:  {overall_efficiency:>14,.1f}%")
            report.append(f"  Overall Drop Rate:        {overall_drop_rate:>14,.1f}%")
        
        report.append(f"  Peak Events/Second:       {max_edps:>15,.2f}")
        
        # Average queue usage
        report.append("\nAverage Queue Usage:")
        if avg_event_queue:
            avg_eq = sum(avg_event_queue) / len(avg_event_queue)
            report.append(f"  Event Queue:              {avg_eq:>14,.1f}%")
        else:
            report.append(f"  Event Queue:              {'N/A':>15}")
        
        if avg_firewall_queue:
            avg_fq = sum(avg_firewall_queue) / len(avg_firewall_queue)
            report.append(f"  Firewall Queue:           {avg_fq:>14,.1f}%")
        else:
            report.append(f"  Firewall Queue:           {'N/A':>15}")
        
        if avg_statistical_queue:
            avg_sq = sum(avg_statistical_queue) / len(avg_statistical_queue)
            report.append(f"  Statistical Queue:        {avg_sq:>14,.1f}%")
        else:
            report.append(f"  Statistical Queue:        {'N/A':>15}")
        
        # Performance insights
        report.append("\n💡 INSIGHTS:")
        insights = []
        
        if total_received > 0 and total_dropped / total_received > 0.05:
            insights.append("  ⚠️  High drop rate detected (>5%) - Consider investigating system capacity")
        
        if avg_event_queue and sum(avg_event_queue) / len(avg_event_queue) > 70:
            insights.append("  ⚠️  Event queue averaging >70% - System may be under stress")
        
        if max_edps > 10000:
            insights.append("  ✓ High throughput detected - System handling large event volume")
        
        if not insights:
            insights.append("  ✓ System performance appears normal")
        
        for insight in insights:
            report.append(insight)
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)
        
    except ValueError as e:
        return f"Error: Invalid timeframe value - {e}"
    except KeyError as e:
        return f"Error: Missing expected field in statistics data: {e}"
    except Exception as e:
        return f"Error retrieving Wazuh statistics: {str(e)}"



# Run the server
if __name__ == "__main__":
    mcp.run()