import json
from datetime import datetime
import os
from jinja2 import Template

class ReportGenerator:
    def __init__(self, output_file, logger):
        self.output_file = output_file
        self.logger = logger
        self.report_dir = 'reports'
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def generate(self, results):
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'results': results
        }

        # Generate HTML report
        self._generate_html(report)
        
        # Generate JSON report
        self._generate_json(report)

    def _generate_html(self, report):
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Penetration Test Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .vulnerability { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
                .critical { border-left: 5px solid #ff0000; }
                .high { border-left: 5px solid #ff9900; }
                .medium { border-left: 5px solid #ffff00; }
                .low { border-left: 5px solid #00ff00; }
            </style>
        </head>
        <body>
            <h1>Penetration Test Report</h1>
            <p>Generated on: {{ report.timestamp }}</p>
            
            <h2>Information Gathering Results</h2>
            <pre>{{ report.results.recon | tojson(indent=2) }}</pre>
            
            <h2>Vulnerabilities Found</h2>
            {% for vuln in report.results.vulnerabilities %}
            <div class="vulnerability {{ vuln.severity.lower() }}">
                <h3>{{ vuln.type }}</h3>
                <p>{{ vuln.description }}</p>
                <p>Severity: {{ vuln.severity }}</p>
            </div>
            {% endfor %}
        </body>
        </html>
        """
        
        html = Template(template).render(report=report)
        with open(f"{self.report_dir}/{self.output_file}.html", 'w') as f:
            f.write(html)

    def _generate_json(self, report):
        with open(f"{self.report_dir}/{self.output_file}.json", 'w') as f:
            json.dump(report, f, indent=4, default=str)
