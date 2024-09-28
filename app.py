from flask import Flask, render_template, request, send_file
import nmap
import requests
import socket
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
from waitress import serve  # Import the Waitress server

app = Flask(__name__)

# Initialize the Nmap PortScanner
nm = nmap.PortScanner()

# Function to scan open ports and detect service versions on a target IP or hostname
def scan_open_ports(target):
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Scanning {target} ({target_ip}) for open ports and service versions...")
    except socket.gaierror:
        print(f"Error: Could not resolve {target}. Skipping...")
        return []

    nm.scan(target_ip, '1-1024', arguments='-sV -A --version-all')
    scan_results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port].get('version', 'unknown')
                scan_results.append({'service': service, 'version': version, 'port': port, 'protocol': proto, 'host': host})

    return scan_results

# Function to check vulnerabilities using Vulners API
def check_vulnerabilities(service, version):
    api_url = "https://vulners.com/api/v3/search/lucene/"
    query = f"{service} {version}" if version != 'unknown' else service
    params = {
        'query': query,
        'apikey': 'YOUR_API_KEY'  # Replace with your actual API key
    }

    response = requests.get(api_url, params=params)

    if response.status_code == 200:
        vulnerabilities = response.json().get('data', {}).get('search', [])
        filtered_vulns = []

        for vuln in vulnerabilities:
            vuln_id = vuln.get('id', 'Unknown')
            description = vuln.get('description', 'No description available')
            service_in_vuln = any([service in vuln_id.lower(), service in description.lower()])
            
            if vuln_id != 'Unknown' and description != 'No description available' and service_in_vuln:
                filtered_vulns.append(f"CVE: {vuln_id} - {description}")
        
        if filtered_vulns:
            return filtered_vulns
        else:
            return [f"No significant vulnerabilities found for {service} {version}."]
    else:
        return [f"Error querying vulnerabilities for {service} {version}: {response.status_code} - {response.text}"]

# Function to generate PDF report
def generate_pdf_report(ip_or_hostname, scan_results, vulnerabilities):
    # Ensure the 'reports' directory exists
    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    # Path for the PDF file
    file_name = os.path.join(report_dir, f"{ip_or_hostname}_vulnerability_report.pdf")
    pdf = canvas.Canvas(file_name, pagesize=letter)
    pdf.setTitle(f"Vulnerability Report for {ip_or_hostname}")

    # Title and Header
    pdf.drawString(30, 750, f"Vulnerability Report for {ip_or_hostname}")
    pdf.drawString(30, 735, "=" * 40)

    y = 700  # Initial position

    for result in scan_results:
        service = result['service']
        version = result['version']
        port = result['port']
        protocol = result['protocol']

        pdf.drawString(30, y, f"Service: {service}, Version: {version}, Port: {port}/{protocol}")
        y -= 15

        for vuln in vulnerabilities.get(service, []):
            pdf.drawString(30, y, vuln)
            y -= 15

            if y <= 50:  # If we reach the bottom of the page, create a new page
                pdf.showPage()
                y = 750

        y -= 30  # Add space between services

    pdf.save()
    return file_name

# Route for the main page
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        targets = request.form['targets'].split(',')
        results = {}
        for target in targets:
            target = target.strip()
            scan_results = scan_open_ports(target)
            if scan_results:
                vulnerabilities = {}
                for result in scan_results:
                    service = result['service']
                    version = result['version']
                    vulnerabilities[service] = check_vulnerabilities(service, version)
                results[target] = {'scan_results': scan_results, 'vulnerabilities': vulnerabilities}
                pdf_file = generate_pdf_report(target, scan_results, vulnerabilities)  # Generate the PDF
                results[target]['pdf_file'] = pdf_file
            else:
                results[target] = {'error': 'Could not scan target.'}

        return render_template('results.html', results=results)

    return render_template('index.html')

# Route to download the PDF report
@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join("reports", filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return f"File {filename} not found!", 404

# Run the application with Waitress
if __name__ == '__main__':
    serve(app, host='127.0.0.1', port=8080)  # Serve the app with Waitress
