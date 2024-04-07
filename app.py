import random


from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_socketio import SocketIO
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import secrets
import string
import requests
from bs4 import BeautifulSoup
import re
import psutil
import socket
import time
import threading
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)



results = []
watched_dir = None

class FileHandler(FileSystemEventHandler):
    def is_temporary_file(self, file_path):
        # Define a list of file extensions that are typically temporary
        temporary_extensions = ['.tmp', '.bak', '.swp', '.~']
        return any(file_path.lower().endswith(ext) for ext in temporary_extensions)

    def on_created(self, event):
        if not self.is_temporary_file(event.src_path):
            result = f"Created: {event.src_path}"
            if result not in results:
                results.append(result)
                socketio.emit('update_results', {'result': result})

    def on_modified(self, event):
        if not self.is_temporary_file(event.src_path):
            result = f"Modified: {event.src_path}"
            if result not in results:
                results.append(result)
                socketio.emit('update_results', {'result': result})

    def on_deleted(self, event):
        if not self.is_temporary_file(event.src_path):
            result = f"Deleted: {event.src_path}"
            if result not in results:
                results.append(result)
                socketio.emit('update_results', {'result': result})

    def on_moved(self, event):
        if not (self.is_temporary_file(event.src_path) or self.is_temporary_file(event.dest_path)):
            result = f"Renamed: {event.src_path} to {event.dest_path}"
            if result not in results:
                results.append(result)
                socketio.emit('update_results', {'result': result})

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/directory_monitoring')
def directory_monitoring():
    return render_template('directory_monitoring.html')

@app.route('/set_directory', methods=['POST'])
def set_directory():
    global watched_dir
    watched_dir = request.form['directoryPath']

    # Clear the results when the directory is changed
    results.clear()

    if watched_dir:
        event_handler = FileHandler()
        observer = Observer()
        observer.schedule(event_handler, path=watched_dir, recursive=True)
        observer.start()

    return render_template('directory_monitoring.html', results=results, watched_dir=watched_dir)

@app.route('/monitor_directory', methods=['POST'])
def monitor_directory():
    directory_path = request.form['directory_path']
    return f"Monitoring directory: {directory_path} for changes"


@app.route('/password_strength_checker')
def password_strength_checker():
    return render_template('password_strength_checker.html')

@app.route('/check_password_strength', methods=['POST'])
def check_password_strength():
    password = request.json['password']
    strength = calculate_strength(password)
    return jsonify({'strength': strength})

def calculate_strength(password):
    length = len(password)
    if length < 8:
        return 'Weak'
    elif length < 12:
        return 'Moderate'
    elif length < 16:
        if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and re.search(r'\d', password) and re.search(r'[^A-Za-z0-9]', password):
            return 'Strong'
    return 'Very Strong'

@app.route('/password_generator')
def password_generator():
    return render_template('password_generator.html')

@app.route('/generate_password', methods=['POST'])
def generate_password():
    # Get criteria for password generation from the form checkboxes
    length = int(request.form['length'])
    uppercase = request.form.get('uppercase') == 'true'
    lowercase = request.form.get('lowercase') == 'true'
    numbers = request.form.get('numbers') == 'true'
    specialChars = request.form.get('specialChars') == 'true'

    charset = ''
    if uppercase:
        charset += string.ascii_uppercase
    if lowercase:
        charset += string.ascii_lowercase
    if numbers:
        charset += string.digits
    if specialChars:
        charset += string.punctuation

    password = ''.join(random.choice(charset) for _ in range(length))

    return jsonify({'password': password})


def check_for_vulnerabilities(url):
    try:
        response = requests.get(url)

        # Check for XSS (Example)
        soup = BeautifulSoup(response.text, 'html.parser')
        xss_vulnerabilities = soup.find_all('script')  # Basic check for script tags

        # Check for SQL Injection (Example)
        if 'sql syntax' in response.text.lower():
            sql_injection_vulnerability = True
        else:
            sql_injection_vulnerability = False

        # Check for sensitive information exposure in headers (Example)
        sensitive_headers = []
        for header in response.headers:
            if 'password' in header.lower() or 'token' in header.lower():
                sensitive_headers.append(header)

        vulnerabilities = {
            'XSS': xss_vulnerabilities,
            'SQL Injection': sql_injection_vulnerability,
            'Sensitive Headers': sensitive_headers
        }

        return vulnerabilities

    except requests.RequestException as e:
        return {'Error': str(e)}

@app.route('/web_scanner')
def index1():
    return render_template('web_scanner.html')

@app.route('/scan', methods=['POST'])
def scan():
    website_url = request.form.get('website_url')

    vulnerabilities = check_for_vulnerabilities(website_url)

    return render_template('web_scanner_results.html', url=website_url, vulnerabilities=vulnerabilities)


@app.route('/scan-another', methods=['GET'])
def scan_another():
    return redirect(url_for('index1'))


@app.route('/sec_header_checker')
def index2():
    return render_template('security_checker.html')

@app.route('/check_headers', methods=['POST'])
def check_headers():
    url = request.form['url']
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # adding http:// if missing

    try:
        response = requests.head(url)
        headers = response.headers
        security_headers = {
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Referrer-Policy': headers.get('Referrer-Policy')
        }
        return render_template('security_header_results.html', url=url, security_headers=security_headers)
    except requests.RequestException as e:
        error_message = f"Error: {e}"
        return render_template('security_header_error.html', error_message=error_message)

@app.route('/code_scanner')
def index3():
    return render_template('code_scanner.html')

@app.route('/scan_code', methods=['POST'])
def scan_code():
    code = request.form['code']
    with open('temp_code.py', 'w') as file:
        file.write(code)

    try:
        result = subprocess.run(['bandit', '-r', 'temp_code.py'], capture_output=True, text=True)
        vulnerabilities = result.stdout
        return render_template('code_scanner_results.html', code=code, vulnerabilities=vulnerabilities)
    except Exception as e:
        error_message = f"Error: {e}"
        return render_template('code_scanner_error.html', error_message=error_message)


# @app.route('/Ransomware_Quiz')
# def quiz():
#     return render_template('Ransomware_Quiz.html')

@app.route('/network_monitoring')
def index6():
    return render_template('network_monitoring.html')

@app.route('/monitor')
def monitor():
    host_ip = socket.gethostbyname(socket.gethostname())
    data = {
        'host_ip': host_ip,
        'bytes_sent': psutil.net_io_counters().bytes_sent,
        'bytes_received': psutil.net_io_counters().bytes_recv,
        'packets_sent': psutil.net_io_counters().packets_sent,
        'packets_received': psutil.net_io_counters().packets_recv
    }
    return data



# HASH GENERATOR
@app.route('/hash_generator')
def index5():
    return render_template('hash_generator.html')


@app.route('/generate')
def generate():
    return render_template('hash_generator_generate.html')

@app.route('/email_phishing_detector')
def index7():
    return render_template('Email_Phishing_Detector.html')

@app.route('/Phishing_Quiz')
def index9():
    return render_template('Phishing_Quiz.html')

@app.route('/Cyber_Laws')
def index8():
    return render_template('Cyber_Laws.html')

@app.route('/Password_Awareness')
def index11():
    return render_template('strongPasswordquiz.html')

@app.route('/Digital_Payment')
def index10():
    return render_template('Digital Payment Security Quiz.html')




@app.route('/verify')
def verify():
    return render_template('hash_generator_verify.html')


@app.route('/generate_hash', methods=['POST'])
def generate_hash():
    file = request.files['file']
    hash_algorithm = request.form['hash_algorithm']

    if file:
        file_content = file.read()
        hash_value = hashlib.new(hash_algorithm, file_content).hexdigest()
        return render_template('hash_generator_result.html', result_text=f"Generated hash: {hash_value}")
    else:
        return render_template('hash_generator_result.html', result_text="No file uploaded.")


@app.route('/verify_hash', methods=['POST'])
def verify_hash():
    file = request.files['file']
    hash_value = request.form['hash_value']
    hash_algorithm = request.form['hash_algorithm']

    if file:
        file_content = file.read()
        computed_hash = hashlib.new(hash_algorithm, file_content).hexdigest()

        if computed_hash == hash_value:
            return render_template('hash_generator_result.html', result_text="Hashes match! File is authentic.")
        else:
            return render_template('hash_generator_result.html', result_text="Hashes do not match! File may be corrupted or tampered.")
    else:
        return render_template('hash_generator_result.html', result_text="No file uploaded.")



if __name__ == '__main__':
    app.run(debug=True)
