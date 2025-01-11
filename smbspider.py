from smb.SMBConnection import SMBConnection
import os
import time
import json
import logging
from alive_progress import alive_bar
from argparse import ArgumentParser
from colorama import Fore, Style
from rich.console import Console

# Initialize rich console
console = Console()

# ASCII Art
ASCII_ART = """
[cyan].▄▄ · • ▌ ▄ ·. ▄▄▄▄· .▄▄ ·  ▄▄▄·▪  ·▄▄▄▄  ▄▄▄ .▄▄▄  
▐█ ▀. ·██ ▐███▪▐█ ▀█▪▐█ ▀. ▐█ ▄███ ██▪ ██ ▀▄.▀·▀▄ █·
▄▀▀▀█▄▐█ ▌▐▌▐█·▐█▀▀█▄▄▀▀▀█▄ ██▀·▐█·▐█· ▐█▌▐▀▀▪▄▐▀▀▄ 
▐█▄▪▐███ ██▌▐█▌██▄▪▐█▐█▄▪▐█▐█▪·•▐█▌██. ██ ▐█▄▄▌▐█•█▌
 ▀▀▀▀ ▀▀  █▪▀▀▀·▀▀▀▀  ▀▀▀▀ .▀   ▀▀▀▀▀▀▀▀•  ▀▀▀ .▀  ▀  | 3KY[/cyan]
"""

# Configure logging
logging.basicConfig(filename="smb_spider.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Track downloaded files
JUICY_EXTENSIONS = ('.txt', '.pdf', '.xlsx', '.xls', '.doc', '.docx', '.ppt', '.pptx', '.log', '.csv', '.json', '.xml', '.md', '.ini', '.cfg', '.conf', '.yaml', '.yml', '.properties')
downloaded_files = []

def log_message(message):
    console.print(f"[green]{message}[/green]")
    logging.info(message)

def error_message(message):
    console.print(f"[red]{message}[/red]")
    logging.error(message)

def connect_to_smb(server_ip, share_name, username="", password="", domain="", port=445):
    """Establishes a connection to the SMB server."""
    conn = SMBConnection(username, password, "smb_spider", server_ip, domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
    assert conn.connect(server_ip, port), "Failed to connect to SMB server."
    return conn

def connect_with_retries(server_ip, share_name, username="", password="", domain="", port=445, retries=3, delay=5):
    """Retries SMB connection in case of failure."""
    for attempt in range(retries):
        try:
            conn = connect_to_smb(server_ip, share_name, username, password, domain, port)
            log_message(f"Connected successfully on attempt {attempt + 1}.")
            return conn
        except Exception as e:
            error_message(f"Connection attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
    raise Exception("Failed to connect after multiple attempts.")

def read_file_content(file_path):
    """Reads and visually displays the content of juicy readable files enclosed in an ASCII box."""
    try:
        console.print(f"[blue]Do you want to read the file {file_path}? (y/n):[/blue]", end=" ")
        choice = input().strip().lower()
        if choice == 'y':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                box_top = "┌" + "─" * 78 + "┐"
                box_bottom = "└" + "─" * 78 + "┘"
                console.print(f"[yellow]{box_top}[/yellow]")
                for line in content.splitlines():
                    wrapped_lines = [line[i:i+76] for i in range(0, len(line), 76)]
                    for wrapped_line in wrapped_lines:
                        console.print(f"[yellow]│[/yellow] {wrapped_line:<76} [yellow]│[/yellow]")
                console.print(f"[yellow]{box_bottom}[/yellow]")
    except Exception as e:
        error_message(f"Failed to read file {file_path}: {e}")

def download_files(conn, share_name, remote_path, local_path, include_ext=None, exclude_ext=None, bar=None, read_juicy_files=False):
    """Recursively downloads files from the SMB share with optional filters."""
    try:
        if not os.path.exists(local_path):
            os.makedirs(local_path)

        files = conn.listPath(share_name, remote_path)
        for file in files:
            if file.isDirectory:
                if file.filename not in ['.', '..']:
                    download_files(conn, share_name, os.path.join(remote_path, file.filename),
                                   os.path.join(local_path, file.filename), include_ext, exclude_ext, bar, read_juicy_files)
            else:
                if include_ext and not file.filename.endswith(tuple(include_ext)):
                    continue
                if exclude_ext and file.filename.endswith(tuple(exclude_ext)):
                    continue

                local_file_path = os.path.join(local_path, file.filename)
                with open(local_file_path, 'wb') as local_file:
                    conn.retrieveFile(share_name, os.path.join(remote_path, file.filename), local_file)
                    log_message(f"Downloaded: [cyan]{local_file_path}[/cyan]")
                    downloaded_files.append(local_file_path)
                    if bar:
                        bar()

                # Optionally read juicy files
                if read_juicy_files and file.filename.endswith(JUICY_EXTENSIONS):
                    read_file_content(local_file_path)
    except Exception as e:
        error_message(f"Error downloading {remote_path}: {e}")

def save_to_json():
    """Saves the list of downloaded files to a JSON file."""
    with open("download_summary.json", "w") as f:
        json.dump(downloaded_files, f, indent=4)

def count_files(conn, share_name, remote_path, total_files):
    """Recursively counts files in the SMB share."""
    files = conn.listPath(share_name, remote_path)
    for file in files:
        if file.isDirectory:
            if file.filename not in ['.', '..']:
                count_files(conn, share_name, os.path.join(remote_path, file.filename), total_files)
        else:
            total_files[0] += 1

if __name__ == "__main__":
    console.print(ASCII_ART)

    parser = ArgumentParser(description="SMB Spider")
    parser.add_argument("--ip", required=True, help="SMB server IP address")
    parser.add_argument("--share", required=True, help="SMB share name")
    parser.add_argument("--username", default="", help="SMB username (optional)")
    parser.add_argument("--password", default="", help="SMB password (optional)")
    parser.add_argument("--domain", default="", help="SMB domain (optional)")
    parser.add_argument("--port", type=int, default=445, help="SMB server port (default: 445)")
    parser.add_argument("--remote_path", default="", help="Initial directory on the SMB share")
    parser.add_argument("--local_path", default="./smb_downloads", help="Directory to save downloaded files")
    parser.add_argument("--include_ext", nargs="*", help="Include only files with these extensions (e.g., .txt .log)")
    parser.add_argument("--exclude_ext", nargs="*", help="Exclude files with these extensions (e.g., .tmp .bak)")
    parser.add_argument("--read", action="store_true", help="Read juicy files (.txt, .pdf, .xlsx, .xls, .doc, .docx, .ppt, .pptx, .log, .csv, .json, .xml, .md, .ini) after downloading")
    args = parser.parse_args()

    log_message("Connecting to SMB server...")
    try:
        conn = connect_with_retries(args.ip, args.share, args.username, args.password, args.domain, args.port)
        log_message("Connected successfully.")

        log_message(f"Starting download from share '[yellow]{args.share}[/yellow]'...")
        total_files = [0]

        # Calculate total files for progress bar
        count_files(conn, args.share, args.remote_path, total_files)

        with alive_bar(total_files[0], title="Downloading files", bar="blocks") as bar:
            download_files(conn, args.share, args.remote_path, args.local_path, args.include_ext, args.exclude_ext, bar, args.read)

        log_message("Download complete. Closing connection.")
        conn.close()
        save_to_json()
        log_message("Connection closed. Summary saved to download_summary.json.")
    except Exception as e:
        error_message(f"Fatal error: {e}")
