from flask import Flask, render_template, request
import nmap
import threading
import time

app = Flask(__name__)
scan_logs = []

def scan_progress(ip_address, arguments):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments=arguments)
    while nm.still_scanning():
        time.sleep(1)
        current_progress = nm.progress
        scan_logs.append(current_progress)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_address = request.form['ip_address']
    scan_types = request.form.getlist('scan_types')  # Get selected scan types
    
    # Perform host discovery to check if the host is up
    nm = nmap.PortScanner()
    host_up = int(nm.scan(hosts=ip_address, arguments='-sn')['nmap']['scanstats']['uphosts']) > 0

    if not host_up:
        return render_template('error.html', message="Host is not up.")

    # Construct arguments for nmap scan based on selected scan types
    arguments = '-p-'
    for scan_type in scan_types:
        if scan_type == 'TCP SYN Scan':
            arguments += ' -sS'
        elif scan_type == 'TCP Connect Scan':
            arguments += ' -sT'
        elif scan_type == 'UDP Scan':
            arguments += ' -sU'
        elif scan_type == 'TCP ACK Scan':
            arguments += ' -sA'
        elif scan_type == 'TCP Window Scan':
            arguments += ' -sW'
        elif scan_type == 'TCP Null Scan':
            arguments += ' -sN'
        elif scan_type == 'TCP FIN Scan':
            arguments += ' -sF'
        elif scan_type == 'TCP Xmas Tree Scan':
            arguments += ' -sX'

    # Version detection and OS detection
    if 'Version Detection (-sV)' in scan_types:
        arguments += ' -sV'
    if 'OS Detection (-O)' in scan_types:
        arguments += ' -O'

    # Initialize logs list to store progress prints
    global scan_logs
    scan_logs = []
    logs = []
    logs.append("Starting scan...")
    
    # Start scan progress in a separate thread
    scan_thread = threading.Thread(target=scan_progress, args=(ip_address, arguments))
    scan_thread.start()

    # Wait for the scan to complete
    scan_thread.join()

    # Extract scan results
    open_ports = []
    if 'tcp' in nm.scaninfo():
        open_ports = nm[ip_address].all_tcp()
    
    # Simulated vulnerability information
    vulnerabilities = {'HTTP': ['CVE-2019-1234', 'CVE-2020-5678']}

    # Add progress prints to the logs list
    logs.append("Scan completed successfully.")
    
    return render_template('results.html', ip_address=ip_address, open_ports=open_ports, vulnerabilities=vulnerabilities, logs=logs, scan_logs=scan_logs)

if __name__ == '__main__':
    app.run(debug=True)

