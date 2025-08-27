"""
Report generation for PHIDS
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from collections import Counter, defaultdict
import pandas as pd

from config import REPORTS_DIR, REPORTING_CONFIG
from src.core.database import DatabaseManager
from src.analysis.log_analyzer import LogAnalyzer


class ReportGenerator:
    """Generate security reports and visualizations"""
    
    def __init__(self):
        self.logger = logging.getLogger("report_generator")
        self.db_manager = DatabaseManager()
        self.log_analyzer = LogAnalyzer()
        self.running = False
        
        # Ensure reports directory exists
        REPORTS_DIR.mkdir(exist_ok=True)
        
        # Setup Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        template_dir.mkdir(exist_ok=True)
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    async def start(self):
        """Start report generation tasks"""
        if self.running:
            self.logger.warning("Report generator already running")
            return
        
        self.logger.info("Starting report generator")
        self.running = True
        
        # Start periodic report generation
        tasks = []
        
        if REPORTING_CONFIG['daily_reports']:
            tasks.append(asyncio.create_task(self._daily_report_loop()))
        
        if REPORTING_CONFIG['weekly_reports']:
            tasks.append(asyncio.create_task(self._weekly_report_loop()))
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            self.logger.info("Report generation tasks cancelled")
    
    async def stop(self):
        """Stop report generation"""
        self.logger.info("Stopping report generator")
        self.running = False
    
    async def _daily_report_loop(self):
        """Generate daily reports"""
        while self.running:
            try:
                # Wait until next day or 24 hours
                await asyncio.sleep(86400)  # 24 hours
                
                if self.running:
                    await self.generate_daily_report()
                    
            except Exception as e:
                self.logger.error(f"Error in daily report loop: {e}")
                await asyncio.sleep(3600)  # Wait 1 hour on error
    
    async def _weekly_report_loop(self):
        """Generate weekly reports"""
        while self.running:
            try:
                # Wait 7 days
                await asyncio.sleep(604800)  # 7 days
                
                if self.running:
                    await self.generate_weekly_report()
                    
            except Exception as e:
                self.logger.error(f"Error in weekly report loop: {e}")
                await asyncio.sleep(86400)  # Wait 1 day on error
    
    async def generate_daily_report(self):
        """Generate daily security report"""
        self.logger.info("Generating daily report")
        
        try:
            # Collect data for last 24 hours
            report_data = await self._collect_daily_data()
            
            # Generate visualizations
            charts = await self._generate_daily_charts(report_data)
            
            # Generate reports in configured formats
            for format_type in REPORTING_CONFIG['report_formats']:
                if format_type == 'html':
                    await self._generate_html_report(report_data, charts, 'daily')
                elif format_type == 'json':
                    await self._generate_json_report(report_data, 'daily')
                elif format_type == 'pdf':
                    await self._generate_pdf_report(report_data, charts, 'daily')
            
            self.logger.info("Daily report generated successfully")
            
        except Exception as e:
            self.logger.error(f"Error generating daily report: {e}")
    
    async def generate_weekly_report(self):
        """Generate weekly security report"""
        self.logger.info("Generating weekly report")
        
        try:
            # Collect data for last 7 days
            report_data = await self._collect_weekly_data()
            
            # Generate visualizations
            charts = await self._generate_weekly_charts(report_data)
            
            # Generate reports in configured formats
            for format_type in REPORTING_CONFIG['report_formats']:
                if format_type == 'html':
                    await self._generate_html_report(report_data, charts, 'weekly')
                elif format_type == 'json':
                    await self._generate_json_report(report_data, 'weekly')
                elif format_type == 'pdf':
                    await self._generate_pdf_report(report_data, charts, 'weekly')
            
            self.logger.info("Weekly report generated successfully")
            
        except Exception as e:
            self.logger.error(f"Error generating weekly report: {e}")
    
    async def _collect_daily_data(self):
        """Collect data for daily report"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        # Get connections
        connections = await self.db_manager.get_recent_connections(hours=24, limit=1000)
        
        # Get alerts
        alerts = await self.db_manager.get_recent_alerts(hours=24, limit=500)
        
        # Get top attackers
        top_attackers = await self.db_manager.get_top_attackers(hours=24, limit=20)
        
        # Get analysis summary
        analysis_summary = self.log_analyzer.get_analysis_summary()
        
        return {
            'period': 'daily',
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'connections': [dict(conn) for conn in connections],
            'alerts': [dict(alert) for alert in alerts],
            'top_attackers': [dict(attacker) for attacker in top_attackers],
            'analysis_summary': analysis_summary,
            'statistics': self._calculate_statistics(connections, alerts)
        }
    
    async def _collect_weekly_data(self):
        """Collect data for weekly report"""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        
        # Get connections
        connections = await self.db_manager.get_recent_connections(hours=168, limit=5000)
        
        # Get alerts
        alerts = await self.db_manager.get_recent_alerts(hours=168, limit=2000)
        
        # Get top attackers
        top_attackers = await self.db_manager.get_top_attackers(hours=168, limit=50)
        
        # Get analysis summary
        analysis_summary = self.log_analyzer.get_analysis_summary()
        
        return {
            'period': 'weekly',
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'connections': [dict(conn) for conn in connections],
            'alerts': [dict(alert) for alert in alerts],
            'top_attackers': [dict(attacker) for attacker in top_attackers],
            'analysis_summary': analysis_summary,
            'statistics': self._calculate_statistics(connections, alerts)
        }
    
    def _calculate_statistics(self, connections, alerts):
        """Calculate summary statistics"""
        # Connection statistics
        total_connections = len(connections)
        unique_ips = len(set(conn['source_ip'] for conn in connections if conn['source_ip']))
        
        # Service breakdown
        service_counts = Counter(conn['service_type'] for conn in connections if conn['service_type'])
        
        # Alert statistics
        total_alerts = len(alerts)
        alert_types = Counter(alert['alert_type'] for alert in alerts if alert['alert_type'])
        severity_counts = Counter(alert['severity'] for alert in alerts if alert['severity'])
        
        # Time-based analysis
        hourly_activity = defaultdict(int)
        for conn in connections:
            if conn['timestamp']:
                try:
                    hour = datetime.fromisoformat(conn['timestamp'].replace('Z', '+00:00')).hour
                    hourly_activity[hour] += 1
                except:
                    pass
        
        return {
            'total_connections': total_connections,
            'unique_source_ips': unique_ips,
            'total_alerts': total_alerts,
            'service_breakdown': dict(service_counts),
            'alert_types': dict(alert_types),
            'severity_distribution': dict(severity_counts),
            'hourly_activity': dict(hourly_activity)
        }
    
    async def _generate_daily_charts(self, report_data):
        """Generate charts for daily report"""
        charts = {}
        
        try:
            # Hourly activity chart
            charts['hourly_activity'] = self._create_hourly_activity_chart(
                report_data['statistics']['hourly_activity'], 'daily'
            )
            
            # Service breakdown pie chart
            charts['service_breakdown'] = self._create_service_breakdown_chart(
                report_data['statistics']['service_breakdown']
            )
            
            # Alert severity chart
            charts['alert_severity'] = self._create_alert_severity_chart(
                report_data['statistics']['severity_distribution']
            )
            
            # Top attackers chart
            charts['top_attackers'] = self._create_top_attackers_chart(
                report_data['top_attackers'][:10]
            )
            
        except Exception as e:
            self.logger.error(f"Error generating daily charts: {e}")
        
        return charts
    
    async def _generate_weekly_charts(self, report_data):
        """Generate charts for weekly report"""
        charts = {}
        
        try:
            # Daily activity trend
            charts['daily_trend'] = self._create_daily_trend_chart(report_data['connections'])
            
            # Service breakdown pie chart
            charts['service_breakdown'] = self._create_service_breakdown_chart(
                report_data['statistics']['service_breakdown']
            )
            
            # Alert types chart
            charts['alert_types'] = self._create_alert_types_chart(
                report_data['statistics']['alert_types']
            )
            
            # Top attackers chart
            charts['top_attackers'] = self._create_top_attackers_chart(
                report_data['top_attackers'][:15]
            )
            
        except Exception as e:
            self.logger.error(f"Error generating weekly charts: {e}")
        
        return charts
    
    def _create_hourly_activity_chart(self, hourly_data, period):
        """Create hourly activity chart"""
        try:
            plt.figure(figsize=(12, 6))
            hours = list(range(24))
            activity = [hourly_data.get(hour, 0) for hour in hours]
            
            plt.bar(hours, activity, color='steelblue', alpha=0.7)
            plt.xlabel('Hour of Day')
            plt.ylabel('Number of Connections')
            plt.title(f'Hourly Activity Distribution ({period.title()})')
            plt.xticks(hours)
            plt.grid(True, alpha=0.3)
            
            chart_path = REPORTS_DIR / f'hourly_activity_{period}_{datetime.now().strftime("%Y%m%d")}.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Error creating hourly activity chart: {e}")
            return None
    
    def _create_service_breakdown_chart(self, service_data):
        """Create service breakdown pie chart"""
        try:
            if not service_data:
                return None
            
            plt.figure(figsize=(8, 8))
            services = list(service_data.keys())
            counts = list(service_data.values())
            
            plt.pie(counts, labels=services, autopct='%1.1f%%', startangle=90)
            plt.title('Service Breakdown')
            
            chart_path = REPORTS_DIR / f'service_breakdown_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Error creating service breakdown chart: {e}")
            return None
    
    def _create_alert_severity_chart(self, severity_data):
        """Create alert severity chart"""
        try:
            if not severity_data:
                return None
            
            plt.figure(figsize=(8, 6))
            severities = list(severity_data.keys())
            counts = list(severity_data.values())
            
            colors = {'low': 'green', 'medium': 'orange', 'high': 'red', 'critical': 'darkred'}
            bar_colors = [colors.get(sev, 'gray') for sev in severities]
            
            plt.bar(severities, counts, color=bar_colors, alpha=0.7)
            plt.xlabel('Severity Level')
            plt.ylabel('Number of Alerts')
            plt.title('Alert Severity Distribution')
            
            chart_path = REPORTS_DIR / f'alert_severity_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Error creating alert severity chart: {e}")
            return None
    
    def _create_top_attackers_chart(self, attacker_data):
        """Create top attackers chart"""
        try:
            if not attacker_data:
                return None
            
            plt.figure(figsize=(12, 8))
            ips = [item['source_ip'] for item in attacker_data]
            counts = [item['connection_count'] for item in attacker_data]
            
            plt.barh(ips, counts, color='crimson', alpha=0.7)
            plt.xlabel('Number of Connections')
            plt.ylabel('Source IP Address')
            plt.title('Top Attacking IP Addresses')
            plt.gca().invert_yaxis()
            
            chart_path = REPORTS_DIR / f'top_attackers_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Error creating top attackers chart: {e}")
            return None
    
    def _create_daily_trend_chart(self, connections):
        """Create daily trend chart for weekly report"""
        try:
            # Group connections by day
            daily_counts = defaultdict(int)
            for conn in connections:
                if conn['timestamp']:
                    try:
                        date = datetime.fromisoformat(conn['timestamp'].replace('Z', '+00:00')).date()
                        daily_counts[date] += 1
                    except:
                        pass
            
            if not daily_counts:
                return None
            
            plt.figure(figsize=(12, 6))
            dates = sorted(daily_counts.keys())
            counts = [daily_counts[date] for date in dates]
            
            plt.plot(dates, counts, marker='o', linewidth=2, markersize=6)
            plt.xlabel('Date')
            plt.ylabel('Number of Connections')
            plt.title('Daily Connection Trend')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            
            chart_path = REPORTS_DIR / f'daily_trend_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Error creating daily trend chart: {e}")
            return None
    
    def _create_alert_types_chart(self, alert_types_data):
        """Create alert types chart"""
        try:
            if not alert_types_data:
                return None
            
            plt.figure(figsize=(10, 6))
            types = list(alert_types_data.keys())
            counts = list(alert_types_data.values())
            
            plt.bar(types, counts, color='darkorange', alpha=0.7)
            plt.xlabel('Alert Type')
            plt.ylabel('Number of Alerts')
            plt.title('Alert Types Distribution')
            plt.xticks(rotation=45, ha='right')
            
            chart_path = REPORTS_DIR / f'alert_types_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)

        except Exception as e:
            self.logger.error(f"Error creating alert types chart: {e}")
            return None

    async def _generate_html_report(self, report_data, charts, period):
        """Generate HTML report"""
        try:
            template = self.jinja_env.get_template('security_report.html')

            html_content = template.render(
                report_data=report_data,
                charts=charts,
                period=period,
                generation_time=datetime.now().isoformat()
            )

            report_file = REPORTS_DIR / f'security_report_{period}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            self.logger.info(f"HTML report generated: {report_file}")

        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")

    async def _generate_json_report(self, report_data, period):
        """Generate JSON report"""
        try:
            report_file = REPORTS_DIR / f'security_report_{period}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            self.logger.info(f"JSON report generated: {report_file}")

        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")

    async def _generate_pdf_report(self, report_data, charts, period):
        """Generate PDF report (placeholder - requires weasyprint)"""
        try:
            # First generate HTML
            template = self.jinja_env.get_template('security_report.html')

            html_content = template.render(
                report_data=report_data,
                charts=charts,
                period=period,
                generation_time=datetime.now().isoformat()
            )

            # Note: PDF generation would require weasyprint or similar
            # For now, we'll save as HTML with PDF extension as placeholder
            report_file = REPORTS_DIR / f'security_report_{period}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf.html'
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            self.logger.info(f"PDF report (HTML) generated: {report_file}")

        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")

    def _create_default_templates(self):
        """Create default report templates"""
        template_dir = Path(__file__).parent / "templates"
        template_file = template_dir / "security_report.html"

        if not template_file.exists():
            html_template = """<!DOCTYPE html>
<html>
<head>
    <title>PHIDS Security Report - {{ period.title() }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; }
        .section { margin: 20px 0; }
        .chart { text-align: center; margin: 20px 0; }
        .chart img { max-width: 100%; height: auto; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .alert-high { color: #e74c3c; font-weight: bold; }
        .alert-medium { color: #f39c12; font-weight: bold; }
        .alert-low { color: #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>PHIDS Security Report</h1>
        <h2>{{ period.title() }} Report</h2>
        <p>Period: {{ report_data.start_time }} to {{ report_data.end_time }}</p>
        <p>Generated: {{ generation_time }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <ul>
            <li><strong>Total Connections:</strong> {{ report_data.statistics.total_connections }}</li>
            <li><strong>Unique Source IPs:</strong> {{ report_data.statistics.unique_source_ips }}</li>
            <li><strong>Total Alerts:</strong> {{ report_data.statistics.total_alerts }}</li>
            <li><strong>Most Targeted Service:</strong> {{ report_data.statistics.service_breakdown.keys() | list | first if report_data.statistics.service_breakdown else 'None' }}</li>
        </ul>
    </div>

    {% if charts.hourly_activity %}
    <div class="section">
        <h2>Activity Patterns</h2>
        <div class="chart">
            <img src="{{ charts.hourly_activity }}" alt="Hourly Activity Chart">
        </div>
    </div>
    {% endif %}

    {% if charts.service_breakdown %}
    <div class="section">
        <h2>Service Breakdown</h2>
        <div class="chart">
            <img src="{{ charts.service_breakdown }}" alt="Service Breakdown Chart">
        </div>
    </div>
    {% endif %}

    {% if report_data.top_attackers %}
    <div class="section">
        <h2>Top Attacking IP Addresses</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Connection Count</th>
            </tr>
            {% for attacker in report_data.top_attackers[:10] %}
            <tr>
                <td>{{ attacker.source_ip }}</td>
                <td>{{ attacker.connection_count }}</td>
            </tr>
            {% endfor %}
        </table>
        {% if charts.top_attackers %}
        <div class="chart">
            <img src="{{ charts.top_attackers }}" alt="Top Attackers Chart">
        </div>
        {% endif %}
    </div>
    {% endif %}

    {% if report_data.alerts %}
    <div class="section">
        <h2>Security Alerts</h2>
        {% if charts.alert_severity %}
        <div class="chart">
            <img src="{{ charts.alert_severity }}" alt="Alert Severity Chart">
        </div>
        {% endif %}
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Description</th>
            </tr>
            {% for alert in report_data.alerts[:20] %}
            <tr>
                <td>{{ alert.timestamp }}</td>
                <td>{{ alert.alert_type }}</td>
                <td class="alert-{{ alert.severity }}">{{ alert.severity }}</td>
                <td>{{ alert.source_ip }}</td>
                <td>{{ alert.description }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    <div class="section">
        <h2>Analysis Summary</h2>
        <p><strong>Attack Patterns Detected:</strong> {{ report_data.analysis_summary.attack_patterns | length }}</p>
        <p><strong>Total Connections Analyzed:</strong> {{ report_data.analysis_summary.total_connections }}</p>
        {% if report_data.analysis_summary.top_attackers %}
        <p><strong>Most Active Attacker:</strong> {{ report_data.analysis_summary.top_attackers.keys() | list | first }}</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            {% if report_data.statistics.total_alerts > 10 %}
            <li>High alert volume detected. Consider reviewing security policies.</li>
            {% endif %}
            {% if report_data.statistics.unique_source_ips > 50 %}
            <li>Large number of unique attackers. Consider implementing IP blocking.</li>
            {% endif %}
            <li>Regular monitoring and analysis of honeypot data is recommended.</li>
            <li>Consider threat intelligence enrichment for unknown IP addresses.</li>
        </ul>
    </div>
</body>
</html>"""

            with open(template_file, 'w', encoding='utf-8') as f:
                f.write(html_template)

    async def generate_custom_report(self, start_time, end_time, report_type='custom'):
        """Generate custom report for specific time period"""
        self.logger.info(f"Generating custom report from {start_time} to {end_time}")

        try:
            # Calculate hours difference
            time_diff = end_time - start_time
            hours = int(time_diff.total_seconds() / 3600)

            # Get data for the period
            connections = await self.db_manager.get_recent_connections(hours=hours, limit=10000)
            alerts = await self.db_manager.get_recent_alerts(hours=hours, limit=5000)
            top_attackers = await self.db_manager.get_top_attackers(hours=hours, limit=50)

            # Filter data by exact time range
            filtered_connections = [
                dict(conn) for conn in connections
                if start_time <= datetime.fromisoformat(conn['timestamp'].replace('Z', '+00:00')) <= end_time
            ]

            filtered_alerts = [
                dict(alert) for alert in alerts
                if start_time <= datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00')) <= end_time
            ]

            report_data = {
                'period': report_type,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'connections': filtered_connections,
                'alerts': filtered_alerts,
                'top_attackers': [dict(attacker) for attacker in top_attackers],
                'analysis_summary': self.log_analyzer.get_analysis_summary(),
                'statistics': self._calculate_statistics(filtered_connections, filtered_alerts)
            }

            # Generate charts
            charts = await self._generate_daily_charts(report_data)

            # Generate HTML report
            await self._generate_html_report(report_data, charts, report_type)

            # Generate JSON report
            await self._generate_json_report(report_data, report_type)

            return report_data

        except Exception as e:
            self.logger.error(f"Error generating custom report: {e}")
            return None
