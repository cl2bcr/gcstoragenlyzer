import html
import json
from datetime import datetime
from typing import Dict, List, Any
import click
from .analyzer import GCSAnalyzer


def generate_sensitive_html_report(data: Dict, output_path: str):
    findings = data.get('findings', [])
    bucket_name = data.get('bucket_name', 'N/A')
    folder_path = data.get('folder_path', '(root)') or '(root)'
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    styles = """
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            margin: 0; 
            background-color: #f4f7f9; 
            line-height: 1.6;
        }
        .container { 
            max-width: 1200px; 
            margin: 20px auto; 
            background: white; 
            padding: 25px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            border-radius: 8px; 
        }
        h1 { 
            color: #2c3e50; 
            border-bottom: 3px solid #e74c3c; 
            padding-bottom: 15px; 
            margin-bottom: 30px;
            text-align: center;
        }
        h2 { 
            color: #2c3e50; 
            border-bottom: 2px solid #e74c3c; 
            padding-bottom: 10px; 
            margin-top: 40px;
        }
        .summary { 
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            padding: 25px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            color: white;
            display: flex; 
            justify-content: space-around; 
            flex-wrap: wrap;
            box-shadow: 0 4px 15px rgba(231, 76, 60, 0.3);
        }
        .summary-box { 
            text-align: center; 
            margin: 10px;
            flex: 1;
            min-width: 150px;
        }
        .summary-box .value { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin-bottom: 5px;
            text-shadow: 0 0 10px rgba(255,255,255,0.3);
        }
        .summary-box .label { 
            color: rgba(255,255,255,0.9); 
            font-size: 0.9em;
            opacity: 0.9;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
            table-layout: fixed;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td { 
            padding: 15px; 
            border: 1px solid #e9ecef; 
            text-align: left; 
            word-wrap: break-word; 
            white-space: pre-wrap; 
            overflow-wrap: break-word;
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
        tr:hover { 
            background-color: #e3f2fd !important;
        }
        .object-name { 
            font-weight: bold; 
            color: #2980b9; 
            width: 30%;
            font-family: 'Courier New', monospace;
        }
        .pattern-name { 
            font-weight: bold; 
            width: 20%; 
            color: #8e44ad;
        }
        .match { 
            font-family: "Courier New", Courier, monospace; 
            background: linear-gradient(135deg, #ffeaa7 0%, #fab1a0 100%);
            padding: 8px 12px; 
            border-radius: 6px; 
            width: 25%;
            font-weight: 500;
            border-left: 4px solid #e17055;
        }
        .validator { 
            font-size: 0.9em; 
            width: 25%;
            padding: 10px;
        }
        .validator.ok { 
            color: #27ae60; 
            background: #d5f4e6;
            border-radius: 4px;
            padding: 5px 10px;
        }
        .validator.fail { 
            color: #e74c3c; 
            background: #fadbd8;
            border-radius: 4px;
            padding: 5px 10px;
        }
        .no-findings {
            text-align: center;
            padding: 60px;
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            border-radius: 10px;
            color: #2c3e50;
            font-size: 1.2em;
            margin: 20px 0;
        }
        .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 0.9em; 
            color: #95a5a6; 
        }
        .severity-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.8em;
            margin: 2px;
        }
        .severity-high { background: #e74c3c; color: white; }
        .severity-medium { background: #f39c12; color: white; }
    </style>
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GCS Sensitive Data Scan Report</title>
        {styles}
    </head>
    <body>
        <div class="container">
            <h1>🔍 GCS Sensitive Data Security Report</h1>

            <div class="summary">
                <div class="summary-box">
                    <div class="value">{html.escape(bucket_name)}</div>
                    <div class="label">Bucket</div>
                </div>
                <div class="summary-box">
                    <div class="value">{html.escape(folder_path)}</div>
                    <div class="label">Scanned Folder</div>
                </div>
                <div class="summary-box">
                    <div class="value" style="color: #ffeaa7;">{len(findings)}</div>
                    <div class="label">🚨 Findings</div>
                </div>
            </div>
    """

    if not findings:
        html_content += """
            <div class="no-findings">
                ✅ No sensitive data found! Your bucket appears to be clean.
            </div>
        """
    else:
        html_content += f"""
            <h2>🚨 Security Findings ({len(findings)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>📄 Object</th>
                        <th>🏷️ Pattern Type</th>
                        <th>🔍 Matched Value</th>
                        <th>✅ Validation</th>
                    </tr>
                </thead>
                <tbody>
        """

        for f in findings:
            validator_name = f.get('validator')
            validator_status_html = ""
            severity_class = "severity-high"

            if validator_name:
                status_ok = f.get('validator_ok', False)
                status_class = "ok" if status_ok else "fail"
                reason = html.escape(f.get('validator_reason', ''))
                validator_status_html = f'''
                    <span class="validator {status_class}">
                        <strong>{html.escape(validator_name)}:</strong> {reason}
                    </span>
                '''
                if status_ok:
                    severity_class = "severity-medium"
            else:
                validator_status_html = '<span class="validator ok">Regex match confirmed</span>'

            pattern_name = html.escape(f.get('pattern_name', 'Unknown'))
            match_value = html.escape(f.get('match_masked', ''))

            html_content += f"""
                    <tr>
                        <td class="object-name">{html.escape(f.get('object', ''))}</td>
                        <td class="pattern-name">
                            <span class="severity-badge {severity_class}">{pattern_name}</span>
                        </td>
                        <td class="match">{match_value}</td>
                        <td>{validator_status_html}</td>
                    </tr>
            """

        html_content += """
                </tbody>
            </table>
        """

    html_content += f"""
            <div class="footer">
                <p>🔒 Generated by gcstoragenlyzer</p>
                <p>Scan completed: {scan_time}</p>
            </div>
        </div>
    </body>
    </html>
    """

    _write_html_report(html_content, output_path, "Sensitive Data Report")


def generate_expose_html_report(data: Dict or List[Dict], output_path: str):
    if isinstance(data, dict):
        data = [data]

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    styles = """
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            margin: 0; 
            background-color: #f4f7f9; 
            line-height: 1.6;
        }
        .container { 
            max-width: 1200px; 
            margin: 20px auto; 
            background: white; 
            padding: 25px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            border-radius: 8px; 
        }
        h1 { 
            color: #2c3e50; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 15px; 
            margin-bottom: 30px;
            text-align: center;
        }
        h2 { 
            color: #2c3e50; 
            border-bottom: 2px solid #3498db; 
            padding-bottom: 10px; 
            margin-top: 40px;
        }
        h3 {
            color: #34495e;
            margin-top: 30px;
        }
        .summary { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 25px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            color: white;
            display: flex; 
            justify-content: space-around; 
            flex-wrap: wrap;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        .summary-box { 
            text-align: center; 
            margin: 10px;
            flex: 1;
            min-width: 150px;
        }
        .summary-box .value { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin-bottom: 5px;
        }
        .summary-box.critical .value { 
            color: #e74c3c; 
            text-shadow: 0 0 10px rgba(231, 76, 60, 0.5);
        }
        .summary-box.warning .value { 
            color: #f39c12; 
            text-shadow: 0 0 10px rgba(243, 156, 18, 0.5);
        }
        .summary-box.safe .value { 
            color: #27ae60; 
            text-shadow: 0 0 10px rgba(39, 174, 96, 0.5);
        }
        .summary-box .label { 
            color: rgba(255,255,255,0.9); 
            font-size: 0.9em;
            opacity: 0.9;
        }
        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            margin: 5px;
            text-transform: uppercase;
            font-size: 0.85em;
        }
        .status-critical { background: #e74c3c; color: white; }
        .status-warning { background: #f39c12; color: white; }
        .status-safe { background: #27ae60; color: white; }

        .tree-container {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .tree-item {
            padding: 12px;
            margin: 8px 0;
            border-left: 4px solid #dee2e6;
            padding-left: 20px;
            position: relative;
            border-radius: 0 6px 6px 0;
            transition: all 0.3s ease;
        }

        .tree-item:hover {
            transform: translateX(5px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .tree-item.public {
            background: #fff5f5;
            border-left-color: #e74c3c;
            color: #c0392b;
            font-weight: 500;
            border-right: 3px solid #e74c3c;
        }

        .tree-item.private {
            background: #f0fff4;
            border-left-color: #27ae60;
            color: #27ae60;
            border-right: 3px solid #27ae60;
        }

        .tree-item.folder {
            font-weight: bold;
            background: linear-gradient(90deg, rgba(52, 152, 219, 0.1), transparent);
            border-left-color: #3498db;
        }

        .icon {
            margin-right: 10px;
            font-size: 1.1em;
        }

        .reason {
            font-size: 0.85em;
            opacity: 0.8;
            margin-top: 5px;
            font-style: italic;
            background: rgba(0,0,0,0.05);
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
            border-top: 4px solid #3498db;
        }

        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }

        .error-message {
            background: #fee;
            border: 1px solid #fcc;
            border-radius: 8px;
            padding: 20px;
            color: #c53030;
            margin: 20px 0;
            border-left: 5px solid #e53e3e;
        }

        .access-mode {
            background: #e3f2fd;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #2196f3;
        }

        .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 0.9em; 
            color: #95a5a6; 
        }
    </style>
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GCS Public Access Scan Report</title>
        {styles}
    </head>
    <body>
        <div class="container">
            <h1>🔍 GCS Public Access Security Report</h1>
            <div style="text-align: center; color: #7f8c8d; margin-bottom: 30px;">
                Generated on: {scan_time}
            </div>
    """

    for i, result in enumerate(data):
        bucket_name = result.get('bucket_name', f'Bucket {i + 1}')

        access_mode = "Uniform" if result.get('uniform_access') else "Fine-Grained"

        if result.get('error'):
            html_content += f"""
            <div class="error-message">
                <h2>⚠️ {html.escape(bucket_name)} ({access_mode})</h2>
                <p><strong>Error:</strong> {html.escape(result['error'])}</p>
            </div>
            """
            continue

        summary = result.get('summary', {})
        status = summary.get('status', 'UNKNOWN').lower()
        message = html.escape(summary.get('message', 'No details found.'))

        status_class = f"status-{status}"
        status_display = status.upper()

        html_content += f"""
            <h2>📦 Bucket: {html.escape(bucket_name)}</h2>
            <div class="access-mode">
                <strong>Access Mode:</strong> {access_mode}
            </div>

            <div class="summary">
                <div class="summary-box {status_class}">
                    <div class="value">{status_display}</div>
                    <div class="label">Security Status</div>
                </div>
                <div class="summary-box">
                    <div class="value">{message}</div>
                    <div class="label">Summary</div>
                </div>
            </div>
        """

        stats_html = ""
        if 'total_objects' in summary or 'public_objects' in summary or 'total_folders' in summary:
            stats_html += '<div class="stats-grid">'
            if 'total_objects' in summary:
                stats_html += f"""
                <div class="stat-card">
                    <div class="stat-number">{summary.get('total_objects', 0)}</div>
                    <p>Total Objects</p>
                </div>
                """
            if 'public_objects' in summary:
                public_count = summary.get('public_objects', 0)
                stats_html += f"""
                <div class="stat-card">
                    <div class="stat-number" style="color: {'#e74c3c' if public_count > 0 else '#27ae60'}">{public_count}</div>
                    <p>🚨 Public Objects</p>
                </div>
                """
            if 'total_folders' in summary:
                stats_html += f"""
                <div class="stat-card">
                    <div class="stat-number">{summary.get('total_folders', 0)}</div>
                    <p>📁 Folders</p>
                </div>
                """
            if 'public_folders' in summary:
                public_folders = summary.get('public_folders', 0)
                stats_html += f"""
                <div class="stat-card">
                    <div class="stat-number" style="color: {'#e74c3c' if public_folders > 0 else '#27ae60'}">{public_folders}</div>
                    <p>🚨 Public Folders</p>
                </div>
                """
            stats_html += '</div>'
            html_content += stats_html

        if result.get('bucket_level_public'):
            html_content += """
            <div class="error-message">
                <h3>🚨 CRITICAL: Entire Bucket is Public!</h3>
                <p><strong>All objects in this bucket are publicly accessible.</strong></p>
                <p>Immediate action required to secure this bucket!</p>
            </div>
            """
            continue

        html_content += """
            <div class="tree-container">
                <h3>📁 Access Control Tree</h3>
        """

        try:
            if result.get('uniform_access'):
                html_content += build_uniform_tree_html(result)
            elif result.get('fine_grained'):
                html_content += build_fine_grained_tree_html(result)
            else:
                html_content += '<p>No tree data available for this access mode.</p>'
        except Exception as tree_error:
            html_content += f"""
            <div class="error-message">
                <p>Error building tree structure: {str(tree_error)}</p>
            </div>
            """

        html_content += "</div>"

    html_content += f"""
            <div class="footer">
                <p>🔒 Generated by gcstoragenlyzer</p>
                <p>Report created on: {scan_time}</p>
            </div>
        </div>
    </body>
    </html>
    """

    _write_html_report(html_content, output_path, "Public Access Report")

def generate_old_html_report(data: Dict, output_path: str):
    old_objects = data.get('old_objects', [])
    bucket_name = data.get('bucket_name', 'N/A')
    folder_path = data.get('folder_path', '(root)') or '(root)'
    threshold = data.get('days_old_threshold', 0)
    total_count = data.get('total_count', 0)
    total_size = data.get('total_size', 0)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def format_size(num_bytes: int) -> str:
        if num_bytes is None: return "N/A"
        if num_bytes < 1024: return f"{num_bytes} B"
        power = 1024
        n = 0
        power_labels = {0: ' B', 1: ' KB', 2: ' MB', 3: ' GB', 4: ' TB'}
        while num_bytes >= power and n < len(power_labels) - 1:
            num_bytes /= power
            n += 1
        return f"{num_bytes:.1f}{power_labels[n]}"

    total_size_str = format_size(total_size)

    styles = """
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            margin: 0; 
            background-color: #f4f7f9; 
            line-height: 1.6;
        }
        .container { 
            max-width: 1200px; 
            margin: 20px auto; 
            background: white; 
            padding: 25px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            border-radius: 8px; 
        }
        h1 { 
            color: #2c3e50; 
            border-bottom: 3px solid #f39c12; 
            padding-bottom: 15px; 
            margin-bottom: 30px;
            text-align: center;
        }
        h2 { 
            color: #2c3e50; 
            border-bottom: 2px solid #f39c12; 
            padding-bottom: 10px; 
            margin-top: 40px;
        }
        .summary { 
            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
            padding: 25px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            color: white;
            display: flex; 
            justify-content: space-around; 
            flex-wrap: wrap;
            box-shadow: 0 4px 15px rgba(243, 156, 18, 0.3);
        }
        .summary-box { 
            text-align: center; 
            margin: 10px;
            flex: 1;
            min-width: 150px;
        }
        .summary-box .value { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin-bottom: 5px;
            text-shadow: 0 0 10px rgba(255,255,255,0.3);
        }
        .summary-box .label { 
            color: rgba(255,255,255,0.9); 
            font-size: 0.9em;
            opacity: 0.9;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
            table-layout: fixed;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td { 
            padding: 15px; 
            border: 1px solid #e9ecef; 
            text-align: left; 
            word-wrap: break-word; 
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            font-weight: 600;
        }
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
        tr:hover { 
            background-color: #fff3cd !important;
        }
        .object-name { 
            font-weight: bold; 
            color: #e67e22; 
            width: 40%;
            font-family: 'Courier New', monospace;
        }
        .age-warning {
            color: #e67e22;
            font-weight: bold;
        }
        .no-findings {
            text-align: center;
            padding: 60px;
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            border-radius: 10px;
            color: #2c3e50;
            font-size: 1.2em;
            margin: 20px 0;
        }
        .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 0.9em; 
            color: #95a5a6; 
        }
    </style>
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GCS Old Objects Report</title>
        {styles}
    </head>
    <body>
        <div class="container">
            <h1>📊 GCS Old Objects Cost Analysis Report</h1>

            <div class="summary">
                <div class="summary-box">
                    <div class="value">{html.escape(bucket_name)}</div>
                    <div class="label">Bucket</div>
                </div>
                <div class="summary-box">
                    <div class="value">{html.escape(folder_path)}</div>
                    <div class="label">Folder</div>
                </div>
                <div class="summary-box">
                    <div class="value">{threshold}</div>
                    <div class="label">Days Threshold</div>
                </div>
                <div class="summary-box">
                    <div class="value" style="color: #ffeaa7;">{total_count}</div>
                    <div class="label">Old Objects</div>
                </div>
                <div class="summary-box">
                    <div class="value" style="color: #ffeaa7;">{total_size_str}</div>
                    <div class="label">Total Size</div>
                </div>
            </div>
    """

    if not old_objects:
        html_content += """
            <div class="no-findings">
                ✅ No old objects found! All data appears to be current.
            </div>
        """
    else:
        html_content += f"""
            <h2>📈 Old Objects Details ({total_count} objects)</h2>
            <table>
                <thead>
                    <tr>
                        <th>📄 Object Name</th>
                        <th>📅 Created</th>
                        <th>⏰ Age (Days)</th>
                        <th>💾 Size</th>
                    </tr>
                </thead>
                <tbody>
        """

        for obj in sorted(old_objects, key=lambda x: x.get('age_days', 0), reverse=True):
            obj_name = html.escape(obj.get('name', 'N/A'))
            created_at_str = obj['created_at'].astimezone().strftime('%Y-%m-%d %H:%M:%S') if obj.get(
                'created_at') else 'N/A'
            age_days = obj.get('age_days', 'N/A')
            size_str = format_size(obj.get('size'))

            age_class = "age-warning" if age_days > threshold * 2 else ""

            html_content += f"""
                    <tr>
                        <td class="object-name">{obj_name}</td>
                        <td>{created_at_str}</td>
                        <td class="{age_class}">{age_days}</td>
                        <td>{size_str}</td>
                    </tr>
            """

        html_content += """
                </tbody>
            </table>
        """

    html_content += f"""
            <div class="footer">
                <p>💰 Generated by gcstoragenlyzer - Cost Optimization Module</p>
                <p>Scan completed: {scan_time}</p>
            </div>
        </div>
    </body>
    </html>
    """

    _write_html_report(html_content, output_path, "Old Objects Report")


def build_uniform_tree_html(result: Dict) -> str:
    html_output = ""

    root_objects_info = result.get('root_objects', {})
    if root_objects_info.get('objects'):
        is_public = root_objects_info.get('status') == 'PUBLIC'
        status_class = 'public' if is_public else 'private'
        icon = "🚨" if is_public else "✅"

        html_output += f"""
        <div class="tree-item {status_class} folder">
            <span class="icon">📁</span> Root Level Objects
            <div class="reason">{root_objects_info.get('status', 'Unknown')} Access</div>
        </div>
        """

        for obj_name in root_objects_info['objects']:
            if isinstance(obj_name, str):
                display_name = obj_name.split('/')[-1]
                html_output += f"""
                <div class="tree-item {status_class}">
                    <span class="icon">📄</span> {html.escape(display_name)}
                </div>
                """
            else:
                html_output += f"""
                <div class="tree-item {status_class}">
                    <span class="icon">📄</span> {html.escape(str(obj_name))}
                </div>
                """

    folders = result.get('folders', [])
    for folder in folders:
        html_output += build_folder_tree_html(folder, 0, is_uniform=True)

    return html_output


def build_fine_grained_tree_html(result: Dict) -> str:
    folder_tree = result.get('folder_tree', {})
    return build_folder_tree_html(folder_tree, 0, is_uniform=False)


def build_folder_tree_html(folder: Dict, level: int, is_uniform: bool = True) -> str:
    html_output = ""
    indent_style = f"margin-left: {level * 20}px;"

    name = folder.get('name', 'N/A')
    is_public = folder.get('is_public', False)
    public_count = folder.get('public_object_count', 0)
    total_count = folder.get('total_object_count', 0)
    reason = folder.get('reason', '')

    if public_count > 0:
        status_class = 'public'
        icon = "🚨"
        status_text = f"MIXED ({public_count}/{total_count} public)"
    else:
        status_class = 'private' if not is_public else 'public'
        icon = "✅" if not is_public else "🚨"
        status_text = "SAFE" if not is_public else "PUBLIC"

    html_output += f"""
    <div class="tree-item {status_class} folder" style="{indent_style}">
        <span class="icon">{icon}</span> {html.escape(name)}/
        <div class="reason">{html.escape(reason or status_text)}</div>
    </div>
    """

    objects = folder.get('objects', [])
    for obj in objects:
        if isinstance(obj, str):
            obj_name = obj.split('/')[-1]
            obj_public = is_public
            obj_status_class = 'public' if obj_public else 'private'
            obj_icon = "🚨" if obj_public else "✅"

            html_output += f"""
            <div class="tree-item {obj_status_class}" style="{indent_style}; margin-left: {(level + 1) * 20}px;">
                <span class="icon">{obj_icon}</span> 📄 {html.escape(obj_name)}
            </div>
            """
        elif isinstance(obj, dict):
            obj_name = obj.get('name', str(obj)).split('/')[-1]
            obj_public = obj.get('is_public', is_public)
            obj_status_class = 'public' if obj_public else 'private'
            obj_icon = "🚨" if obj_public else "✅"

            html_output += f"""
            <div class="tree-item {obj_status_class}" style="{indent_style}; margin-left: {(level + 1) * 20}px;">
                <span class="icon">{obj_icon}</span> 📄 {html.escape(obj_name)}
            </div>
            """
        else:
            obj_name = str(obj).split('/')[-1] if '/' in str(obj) else str(obj)
            html_output += f"""
            <div class="tree-item private" style="{indent_style}; margin-left: {(level + 1) * 20}px;">
                <span class="icon">📄</span> {html.escape(obj_name)} [Unknown Type]
            </div>
            """

    subfolders = folder.get('subfolders', [])
    for subfolder in subfolders:
        html_output += build_folder_tree_html(subfolder, level + 1, is_uniform)

    return html_output


def _write_html_report(content: str, output_path: str, report_type: str):
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        click.secho(f"✅ {report_type} HTML report created: {output_path}", fg='green')
    except Exception as e:
        click.secho(f"❌ Error writing {report_type} file: {e}", fg='red')