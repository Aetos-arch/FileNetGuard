# Why FileNetGuard ?

FileNetGuard is a security integrity verification software designed for Linux servers 🐧 and embedded systems ✈️. It provides detection against unauthorized modifications to protect the integrity of your system and network.

## Features

FileNetGuard offers the following key features:

- Regular security audits for files using advanced hashing algorithm (SHA-256) and network behavior verification algorithms 🔍
- Detailed reports indicating any unauthorized modifications on files or ports (from closed to open, from unlistened to listened) 📋
- Export the database to CSV files for streamlined reporting and user friendly investigation 🗄️
- Report automation 🤖

## Getting Started 🚀

To use FileNetGuard, follow these simple steps:

### Install Python3 if you don't already have it
On ArchLinux : 
```bash
sudo pacman -Syu
sudo pacman -S python3
python3 --version
```
On Debian : 
```bash
sudo apt update
sudo apt install python3
python3 --version
```

### Clone this repository
```bash
git clone https://github.com/Aetos-arch/FileNetGuard.git
cd FileNetGuard
```

### Use basic commands
```bash
usage: FileNetGuard.py [-h] [--init] [--report] [--openport] [--exportdb] [--schedule_periodic_report] [--port PORT] [--debug]

options:
  -h, --help            show this help message and exit
  --init                Initialize
  --report              Generate a report
  --openport            Open a port
  --exportdb            Export database in txt files
  --schedule_periodic_report
                        Schedule periodic report
  --port PORT           Specify the port to open
  --debug               Enable debug mode

```

🚀 FileNetGuard initializer:

```bash
python3 FileNetGuard.py --init
```

🗓️ Generate a report:


```bash
python3 FileNetGuard.py --report
```
📊 Export database in CSV format:

```bash
python3 FileNetGuard.py --exportdb
```

🔁 Automate report generation:

```bash
python3 FileNetGuard.py --schedule_periodic_report
```
## Contribution

We welcome contributions from the open-source community to enhance FileNetGuard's capabilities and security. Please read our contribution guidelines for more information.

## License

FileNetGuard is released under the Apache License. You are free to use, modify, and distribute this software.
