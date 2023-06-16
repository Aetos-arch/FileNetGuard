import sqlite3
import argparse
import json
import os
import hashlib
import socket
import psutil
import datetime
import subprocess
import logging
import sys

DB_FILE = "FileNetGuard.db"
CONF_SUPERVISED_FOLDERS = "FileNetGuard_conf.json"
LOG_FILE = "FileNetGuard.log"

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG)
logger = logging.getLogger()

def is_port_open(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(('localhost', port))
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def is_port_listening(port):
    connections = psutil.net_connections()
    for conn in connections:
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
            return True
    return False

def get_current_date():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def init():
    init_db()
    logger.info("Database created! DB_FILE = %s", DB_FILE)
    
    init_conf()
    logger.info("Configuration file created! CONF_SUPERVISED_FOLDERS = %s", CONF_SUPERVISED_FOLDERS)

    init_file_data()
    logger.info("Files monitored!")
   
    init_port_data()
    logger.info("Ports monitored!")

def init_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        logging.info("Database file deleted.")
    else:
        logging.info("Creating a database for the first time.")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Supervised_File (
            path TEXT PRIMARY KEY,
            hash TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Supervised_Port (
            port_number INTEGER PRIMARY KEY,
            state TEXT,
            is_listening INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Report (
            report_id INTEGER PRIMARY KEY,
            date TEXT,
            result TEXT,
            description TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS File_Modification (
            file_modification_id INTEGER PRIMARY KEY,
            report_id INTEGER,
            path TEXT,
            file_modification_date TEXT,
            old_hash TEXT,
            new_hash TEXT,
            FOREIGN KEY (report_id) REFERENCES Report (report_id),
            FOREIGN KEY (path) REFERENCES Supervised_File (path)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Port_Modification (
            port_modification_id INTEGER PRIMARY KEY,
            report_id INTEGER,
            port_number INTEGER,
            port_modification_date TEXT,
            old_state TEXT,
            new_state TEXT,
            old_is_listening INTEGER,
            new_is_listening INTEGER,
            FOREIGN KEY (report_id) REFERENCES Report (report_id),
            FOREIGN KEY (port_number) REFERENCES Supervised_Port (port_number)
        )
    ''')

    conn.close()

def init_conf():
    supervised_folders = []

    while True:
        try:
            path = input("Enter a folder path to supervise (or 'q' to finish): ")
            if path.lower() == "q":
                break
            supervised_folders.append({"path": path})
        except Exception as e:
            print("Error while entering the path:", str(e))

    data = {"supervised_folders": supervised_folders}

    try:
        with open(CONF_SUPERVISED_FOLDERS, "w") as f:
            json.dump(data, f, indent=4)
        print("FileNetGuard_conf.json file created successfully.")
    except Exception as e:
        print("Error while creating the JSON file:", str(e))

def init_file_data():
    try:
        with open(CONF_SUPERVISED_FOLDERS, "r") as f:
            data = json.load(f)
            supervised_folders = data.get("supervised_folders", [])
    except Exception as e:
        logging.error("Error while reading the configuration file: %s", str(e))
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    for folder in supervised_folders:
        path = folder.get("path", "")
        if not path:
            logging.warning("Invalid path: %s", path)
            continue

        for root, _, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                try:
                    with open(file_path, "rb") as file:
                        content = file.read()
                        hash_sha256 = hashlib.sha256(content).hexdigest()
                except Exception as e:
                    logging.error("Error while processing the file %s: %s", file_path, str(e))
                    continue

                try:
                    cursor.execute("INSERT OR IGNORE INTO Supervised_File (path, hash) VALUES (?, ?)", (file_path, hash_sha256))
                except Exception as e:
                    logging.error("Error while inserting the file %s: %s", file_path, str(e))
                    continue

    conn.commit()
    conn.close()

def init_port_data():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT port_number FROM Supervised_Port")
    existing_ports = set(row[0] for row in cursor.fetchall())

    ports = range(1, 65536)  # Check ports from 1 to 65535

    for port in ports:
        if port in existing_ports:
            continue

        try:
            state = "Closed"
            is_listening = 0

            if is_port_open(port):
                state = "Open"
                is_listening = 1 if is_port_listening(port) else 0

            cursor.execute("INSERT INTO Supervised_Port (port_number, state, is_listening) VALUES (?, ?, ?)",
                           (port, state, is_listening))
        except Exception as e:
            print(f"Error while monitoring port {port}:", str(e))
            continue

    conn.commit()
    conn.close()

def generate_report():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    print("Generating report...")
    cursor.execute("INSERT INTO Report (date, result, description) VALUES (?, ?, ?)",
                   (get_current_date(), "", ""))

    report_id = cursor.lastrowid

    print("Comparing hashes...")
    cursor.execute("SELECT path, hash FROM Supervised_File")
    files_from_db = cursor.fetchall()
    
    modified_files = []
    for file_info in files_from_db:
        path, hash_value = file_info

        try:
            with open(path, "rb") as file:
                content = file.read()
                current_hash = hashlib.sha256(content).hexdigest()

            if current_hash != hash_value:
                modified_files.append((path, hash_value, current_hash))
        except Exception as e:
            print(f"Error processing file {path}: {str(e)}")
            continue

    print("Comparing ports...")
    cursor.execute("SELECT port_number, state, is_listening FROM Supervised_Port")
    ports_from_db = cursor.fetchall()

    modified_ports = []
    for port_info in ports_from_db:
        port_number, old_state, old_is_listening = port_info

        try:
            new_state = "Closed"
            new_is_listening = 0

            if is_port_open(port_number):
                new_state = "Open"
                new_is_listening = 1 if is_port_listening(port_number) else 0

            if new_is_listening != old_is_listening:
                modified_ports.append((port_number, old_state, new_state, old_is_listening, new_is_listening))
        except Exception as e:
            print(f"Error processing port {port_number}: {str(e)}")
            continue

    if modified_files:
        file_modifications = [(report_id, path, get_current_date(), old_hash, new_hash)
                              for path, old_hash, new_hash in modified_files]
        cursor.executemany("""
            INSERT INTO File_Modification (report_id, path, file_modification_date, old_hash, new_hash)
            VALUES (?, ?, ?, ?, ?)
        """, file_modifications)

    if modified_ports:
        port_modifications = [(report_id, port_number, get_current_date(), old_state, new_state, old_is_listening, new_is_listening)
                            for port_number, old_state, new_state, old_is_listening, new_is_listening in modified_ports]

        cursor.executemany("""
            INSERT INTO Port_Modification (report_id, port_number, port_modification_date,
                                        old_state, new_state, old_is_listening, new_is_listening)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, port_modifications)

    conn.commit()

    if modified_files or modified_ports:
        result = "Changes detected"
        description = f"{len(modified_files)} file(s) modified and {len(modified_ports)} port(s) modified."
    else:
        result = "No Changes"
        description = "No file or listening port changes detected."

    print(f"Result: {result}")
    print(f"Description: {description}")

    cursor.execute("UPDATE Report SET result = ?, description = ? WHERE report_id = ?",
                   (result, description, report_id))

    conn.commit()
    conn.close()


def open_port(port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        server_socket.bind(('localhost', port))
        
        server_socket.listen(1)
        
        print(f"Port {port} is now open and listening.")
        
        while True:
            client_socket, client_address = server_socket.accept()
            
            print(f"Received connection from {client_address}")
            
            client_socket.close()
            
    except Exception as e:
        print(f"Error opening port: {str(e)}")
        
    finally:
        server_socket.close()

def exportdb():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]

    export_folder = "DataBaseExport"
    if not os.path.exists(export_folder):
        os.makedirs(export_folder)

    for table in tables:
        file_path = os.path.join(export_folder, f"{table}.csv")

        cursor.execute(f"SELECT * FROM {table};")
        table_data = cursor.fetchall()

        with open(file_path, "w") as file:
            for row in table_data:
                file.write(",".join(str(value) for value in row))
                file.write("\n")

    conn.close()
    print("Database exported successfully.")

def schedule_periodic_report():
  # Check if cronie package is installed
    process = subprocess.run(['pacman', '-Qs', 'cronie'], capture_output=True, text=True)
    
    if process.returncode != 0:
        # cronie package is not installed, install and enable it
        print("cronie package is not installed. Installation will begin...")
        
        # Install cronie package
        install_process = subprocess.run(['sudo', 'pacman', '-Sy', 'cronie'], capture_output=True, text=True)
        
        if install_process.returncode == 0:
            print("cronie package has been installed successfully.")
            
            # Enable cronie service
            enable_process = subprocess.run(['sudo', 'systemctl', 'enable', 'cronie.service'], capture_output=True, text=True)
            
            if enable_process.returncode == 0:
                print("cronie service has been enabled successfully.")
                return True
            else:
                print("Error enabling cronie service:", enable_process.stderr)
        else:
            print("Error installing cronie package:", install_process.stderr)
    else:
        print("cronie package is already installed.")

    while True:
        try:
            days = int(input("Enter the number of days between each execution: "))
            hours = int(input("Enter the number of hours between each execution: "))
            minutes = int(input("Enter the number of minutes between each execution: "))
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Format the cron schedule string
    schedule = f"{minutes} {hours} * * */{days}"

    # Get the absolute path to the Python script
    script_path = os.path.abspath(__file__)

    # Set up the cron command
    cron_command = f"python {script_path} --report"

    try:
        # Use subprocess to add the cron job
        subprocess.run(['crontab', '-l'], check=True, capture_output=True, text=True)
        subprocess.run(['echo', cron_command, '|', 'crontab', '-'], check=True, capture_output=True, text=True)
        print("Cron job successfully scheduled.")
    except subprocess.CalledProcessError as e:
        print(f"Error scheduling cron job: {e.stderr}")

def setup_logging(debug):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, filename=LOG_FILE, filemode="w")
    if debug:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(level)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger("").addHandler(console)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--init', action='store_true', help="Initialize")
    parser.add_argument('--report', action='store_true', help="Generate a report")
    parser.add_argument('--openport', action='store_true', help="Open a port")
    parser.add_argument('--exportdb', action='store_true', help="Export database in txt files")
    parser.add_argument('--schedule_periodic_report', action='store_true', help="Schedule periodic report")
    parser.add_argument('--port', type=int, help="Specify the port to open")
    parser.add_argument('--debug', action='store_true', help="Enable debug mode")

    args = parser.parse_args()

    setup_logging(args.debug)

    if args.init:
        logging.info("Initializing...")
        init()
    elif args.report:
        logging.info("Generating a report...")
        generate_report()
    elif args.openport:
        if args.port:
            logging.info("Opening port {}...".format(args.port))
            open_port(args.port)
        else:
            print("Please specify the port using the --port argument.")
    elif args.schedule_periodic_report:
        logging.info("Scheduling periodic report...")
        schedule_periodic_report()
    elif args.exportdb:
        logging.info("Exporting database in CSV files...")
        exportdb()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()