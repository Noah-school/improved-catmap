from flask import Flask, render_template, send_file, abort, request, redirect, url_for, session
import os
import subprocess
import configparser

app = Flask(__name__)
app.secret_key = os.urandom(24)

config = configparser.ConfigParser()
config.read('catmap.conf')
username = config.get('DEFAULT', 'username')
password = config.get('DEFAULT', 'password')
ssl_cert = config.get('DEFAULT', 'ssl_cert')
ssl_key = config.get('DEFAULT', 'ssl_key')

output_folder = "./output"
image_file = "epd_image.png"
image_path = os.path.join(output_folder, image_file)
scan_results = os.path.join(output_folder, "scan_results.json")

console_output = []

def check_credentials(input_username, input_password):
    return input_username == username and input_password == password

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        input_username = request.form.get("username")
        input_password = request.form.get("password")
        if check_credentials(input_username, input_password):
            session['logged_in'] = True
            return redirect(url_for("home"))
        else:
            return render_template("index.html", error="Invalid username or password")
    return render_template("index.html")

@app.route("/home")
def home():
    if not session.get('logged_in'):
        return redirect(url_for("index"))
    return render_template("home.html")

@app.route("/image")
def display_image():
    if not session.get('logged_in'):
        return redirect(url_for("index"))
    if os.path.exists(image_path) and os.path.isfile(image_path):
        return send_file(image_path, mimetype="image/png")
    abort(404, description="Image not found")

@app.route("/hosts")
def get_hosts():
    if not session.get('logged_in'):
        return redirect(url_for("index"))
    if os.path.exists(scan_results) and os.path.isfile(scan_results):
        with open(scan_results, "r") as file:
            data = file.read()
        return data, 200, {"Content-Type": "application/json"}
    abort(404, description="Hosts file not found")

@app.route("/run_main", methods=["POST"])
def run_main():
    if not session.get('logged_in'):
        return redirect(url_for("index"))
    args = request.json.get("args", [])
    try:
        result = subprocess.run([os.path.join(".venv", "Scripts", "python.exe"), "main.py"] + args, capture_output=True, text=True, check=True)
        console_output.append(result.stdout)
        return result.stdout, 200, {"Content-Type": "text/plain"}
    except subprocess.CalledProcessError as e:
        console_output.append(e.stdout + e.stderr)
        return e.stdout + e.stderr, 500, {"Content-Type": "text/plain"}

@app.route("/run_ip", methods=["POST"])
def run_ip():
    if not session.get('logged_in'):
        return redirect(url_for("index"))
    args = request.json.get("args", [])
    try:
        result = subprocess.run([os.path.join(".venv", "Scripts", "python.exe"), "ip.py"] + args, capture_output=True, text=True, check=True)
        console_output.append(result.stdout)
        return result.stdout, 200, {"Content-Type": "text/plain"}
    except subprocess.CalledProcessError as e:
        console_output.append(e.stdout + e.stderr)
        return e.stdout + e.stderr, 500, {"Content-Type": "text/plain"}

@app.route("/console_output")
def get_console_output():
    if not session.get('logged_in'):
        return redirect(url_for("index"))
    return "\n".join(console_output), 200, {"Content-Type": "text/plain"}

@app.route("/console")
def console():
    if not session.get('logged_in'):
        return redirect(url_for("index"))
    return render_template("console.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=(ssl_cert, ssl_key))
