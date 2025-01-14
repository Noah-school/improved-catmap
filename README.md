# Catmap Network Scanner

Catmap is a network scanning tool that uses Nmap and Searchsploit to identify and analyze devices on a network. It includes a web interface built with Flask and can display results on an e-ink display.

## Features

- Network scanning using Nmap
- Exploit search using Searchsploit
- Web interface for viewing scan results
- E-ink display support for scan results
- Authentication for web interface

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/catmap.git
    cd catmap/newSCANNER
    ```

2. Create a virtual environment and activate it:
    ```bash
    python -m venv .venv
    .venv\Scripts\activate  # On Windows
    source .venv/bin/activate  # On Unix or MacOS
    ```

3. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

4. Configure the application:
    - Copy `catmap.conf.example` to `catmap.conf` and update the configuration values.

5. Generate SSL certificates (see `cert/howto.md` for instructions).

## Usage

### Running the Web Interface

Start the Flask web server:
```bash
python website.py
```

Access the web interface at `https://localhost`.

### Running the Network Scanner

Run the main scanner script:
```bash
python main.py
```

### Running the IP Script

Run the IP script to get network information:
```bash
python ip.py
```

## How It Works

1. **Network Scanning**: The `main.py` script performs a network scan using Nmap. It first pings all hosts in the specified network range to identify active hosts. Then, it runs Nmap on the active hosts to gather detailed information about open ports, services, and operating systems.

2. **Exploit Search**: The `search.py` script uses Searchsploit to find potential exploits for the identified services and devices. It extracts queries from the Nmap scan results and runs Searchsploit to find relevant exploits.

3. **Web Interface**: The `website.py` script provides a Flask-based web interface for viewing scan results. Users can log in with a username and password, view scan results, and trigger new scans.

4. **E-ink Display**: The `lib/display.py` and `lib/simulate_eink.py` scripts handle displaying scan results on an e-ink display. The display is updated with the latest scan results and can show a list of active hosts and their details.

5. **Configuration**: The application uses a configuration file `catmap.conf` for settings such as username, password, and SSL certificates. Ensure this file is properly configured before running the application.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
