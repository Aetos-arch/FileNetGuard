import sqlite3
import argparse
import json
import os
import hashlib
import socket
import psutil
import datetime

DB_FILE = "FileNetGuard.db"
CONF_SUPERVISED_FOLDERS = "FileNetGuard_conf.json"

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
    print("╔═══════════════════════════════════════════╗")
    print("║             Database created!             ║")
    print("║             DB_FILE = {}                  ".format(DB_FILE))
    print("╚═══════════════════════════════════════════╝\n")
    
    init_conf()
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║          Configuration file created!                              ║")
    print("║          CONF_SUPERVISED_FOLDERS = {}               ".format(CONF_SUPERVISED_FOLDERS))
    print("╚═══════════════════════════════════════════════════════════════════╝\n")
    
    init_file_data()
    print("╔═════════════════════════════════╗")
    print("║         Files monitored!        ║")
    print("╚═════════════════════════════════╝\n")
    
    init_port_data()
    print("╔═════════════════════════════╗")
    print("║       Ports monitored!      ║")
    print("╚═════════════════════════════╝")




def init_db():
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
        print("Error while reading the configuration file:", str(e))
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    for folder in supervised_folders:
        path = folder.get("path", "")
        if not path:
            print("Invalid path:", path)
            continue

        for root, _, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                try:
                    with open(file_path, "rb") as file:
                        content = file.read()
                        hash_sha256 = hashlib.sha256(content).hexdigest()
                except Exception as e:
                    print(f"Error while processing the file {file_path}:", str(e))
                    continue

                try:
                    cursor.execute("INSERT OR IGNORE INTO Supervised_File (path, hash) VALUES (?, ?)", (file_path, hash_sha256))
                except Exception as e:
                    print(f"Error while inserting the file {file_path}:", str(e))
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

    # Récupérer la liste des tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]

    # Vérifier si le dossier d'export existe, sinon le créer
    export_folder = "DataBaseExport"
    if not os.path.exists(export_folder):
        os.makedirs(export_folder)

    # Exporter chaque table dans un fichier texte séparé
    for table in tables:
        file_path = os.path.join(export_folder, f"{table}.txt")

        cursor.execute(f"SELECT * FROM {table};")
        table_data = cursor.fetchall()

        with open(file_path, "w") as file:
            # Écrire les données de la table dans le fichier
            for row in table_data:
                file.write(",".join(str(value) for value in row))
                file.write("\n")

    conn.close()

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--init', action='store_true', help="Initialize")
    parser.add_argument('--report', action='store_true', help="Generate a report")
    parser.add_argument('--openport', action='store_true', help="Open a port")
    parser.add_argument('--exportdb', action='store_true', help="Export database in txt files")

    args = parser.parse_args()
    if args.init:
        init()
    elif args.report:
        generate_report()
    elif args.openport:
        open_port(8090)
    elif args.exportdb:
        exportdb()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()