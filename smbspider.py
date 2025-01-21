import os
import time
import json
import logging
import re
from argparse import ArgumentParser
from thefuzz import fuzz
from smb.SMBConnection import SMBConnection
from smb.base import NotConnectedError, SMBTimeout
from alive_progress import alive_bar
from colorama import Fore, Style
from rich.console import Console
import questionary
import sqlite3
import hashlib  # --- NEW ---

console = Console()

# =====================
# Global variables
# =====================
downloaded_files = []
downloaded_metadata = []

# --- NEW ---
hidden_read_data = []  # Will store content from all "juicy" files if --hidden-read is enabled.

# =====================
# ASCII Art
# =====================
ASCII_ART = """
[cyan]
   ▄▄▄▄▄   █▀▄▀█ ███      ▄▄▄▄▄   █ ▄▄  ▄█ ██▄   ▄███▄   █▄▄▄▄ 
  █     ▀▄ █ █ █ █  █    █     ▀▄ █   █ ██ █  █  █▀   ▀  █  ▄▀ 
▄  ▀▀▀▀▄   █ ▄ █ █ ▀ ▄ ▄  ▀▀▀▀▄   █▀▀▀  ██ █   █ ██▄▄    █▀▀▌  
 ▀▄▄▄▄▀    █   █ █  ▄▀  ▀▄▄▄▄▀    █     ▐█ █  █  █▄   ▄▀ █  █  
              █  ███               █     ▐ ███▀  ▀███▀     █   
             ▀                      ▀                     ▀    v1.4[/cyan]
[purple]diego.collao.albornoz@gmail.com | dcollao.pages.dev | @3ky_sec [/purple]
             """

# =====================
# File extension constants
# =====================
JUICY_EXTENSIONS = (
    '.txt', '.pdf', '.log', '.csv', '.json', '.xml',
    '.md', '.ini', '.cfg', '.conf', '.yaml', '.yml',
    '.properties'
)

# =====================
# Logs
# =====================
def log_message(message: str) -> None:
    console.print(f"[green]{message}[/green]")
    logging.info(message)

def error_message(message: str) -> None:
    console.print(f"[red]{message}[/red]")
    logging.error(message)

def set_log_level(log_level_str: str) -> None:
    """
    Sets the logging level based on the string provided.
    Valid options: DEBUG, INFO, WARNING, ERROR, CRITICAL
    """
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level_str}")
    logging.getLogger().setLevel(numeric_level)

# =====================
# SQLite Persistence
# =====================
def init_database(db_path: str = "smb_spider.db") -> sqlite3.Connection:
    """
    Initializes or connects to the local SQLite database
    and creates the 'downloaded_files' table if it doesn't exist.
    """
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS downloaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_name TEXT NOT NULL,
            remote_path TEXT NOT NULL,
            local_path TEXT NOT NULL,
            last_write_time INTEGER,
            downloaded_at TEXT NOT NULL
        );
    """)
    conn.commit()
    return conn

def is_already_downloaded(
    db_conn: sqlite3.Connection,
    share_name: str,
    remote_path: str,
    last_write_time: int
) -> bool:
    """
    Checks if a file with the given share_name + remote_path
    was already downloaded and if its last_write_time matches.
    """
    cursor = db_conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) 
        FROM downloaded_files
        WHERE share_name = ?
          AND remote_path = ?
          AND last_write_time = ?
    """, (share_name, remote_path, last_write_time))
    result = cursor.fetchone()
    return (result[0] > 0)

def record_downloaded_file(
    db_conn: sqlite3.Connection,
    share_name: str,
    remote_path: str,
    local_file_path: str,
    last_write_time: int
) -> None:
    """
    Records a successfully downloaded file in the SQLite database.
    """
    cursor = db_conn.cursor()
    cursor.execute("""
        INSERT INTO downloaded_files
        (share_name, remote_path, local_path, last_write_time, downloaded_at)
        VALUES (?, ?, ?, ?, ?)
    """, (share_name, remote_path, local_file_path, last_write_time, time.ctime()))
    db_conn.commit()

def remove_downloaded_file(
    db_conn: sqlite3.Connection,
    share_name: str,
    remote_path: str,
    last_write_time: int
) -> None:
    """
    Removes a downloaded file entry from the database,
    in case the local file is missing or we want to re-download it.
    """
    cursor = db_conn.cursor()
    cursor.execute("""
        DELETE FROM downloaded_files
        WHERE share_name = ?
          AND remote_path = ?
          AND last_write_time = ?
    """, (share_name, remote_path, last_write_time))
    db_conn.commit()

# =====================
# SMB Connection
# =====================
def connect_to_smb(
    server_ip: str,
    share_name: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    port: int = 445
) -> SMBConnection:
    """
    Creates and returns an SMBConnection object.
    """
    conn = SMBConnection(
        username,
        password,
        "smb_spider",
        server_ip,
        domain=domain,
        use_ntlm_v2=True,
        is_direct_tcp=True
    )

    try:
        connected = conn.connect(server_ip, port)
        if not connected:
            raise ConnectionError("Failed to connect to SMB server.")
    except (NotConnectedError, SMBTimeout) as e:
        raise ConnectionError(
            f"Error connecting to SMB server at {server_ip}:{port} -> {e}"
        )

    return conn

def connect_with_retries(
    server_ip: str,
    share_name: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    port: int = 445,
    retries: int = 3,
    delay: int = 5
) -> SMBConnection:
    """
    Tries to connect multiple times before giving up.
    """
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

# =====================
# Reading file content (Interactive)
# =====================
def read_file_content(file_path: str) -> None:
    """
    Prompt the user to decide if they want to display the file's content
    in the console using questionary confirm.
    """
    try:
        choice = questionary.confirm(
            f"Do you want to read the file {file_path}?"
        ).ask()
        if choice:
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

# --- NEW ---
def hidden_read_file_content(file_path: str) -> None:
    """
    Silently read the entire content of a file (if it is 'juicy') 
    and store it in hidden_read_data for later JSON export.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            hidden_read_data.append({
                "file_path": file_path,
                "content": content
            })
    except Exception as e:
        error_message(f"Failed to hidden-read file {file_path}: {e}")

# =====================
# Keyword searching (Regex)
# =====================
def search_for_keywords(file_path: str, pattern: str) -> None:
    """
    Searches the downloaded file for certain keywords or patterns
    using regex. Prints any matches found and logs them.
    Example pattern: "password|credential|secret"
    """
    if not pattern:
        return

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            regex = re.compile(pattern, re.IGNORECASE)
            matches = regex.findall(content)
            if matches:
                unique_matches = set(matches)
                log_message(
                    f"[bold yellow]Keyword(s) found in {file_path}:[/bold yellow] "
                    f"{', '.join(unique_matches)}"
                )
    except Exception as e:
        error_message(f"Failed to search in file {file_path}: {e}")

# =====================
# Fuzzy searching
# =====================
def fuzzy_search_in_file(file_path: str, fuzzy_words: list[str], fuzzy_threshold: int) -> None:
    """
    Performs a fuzzy search in the file contents for each word in 'fuzzy_words'.
    Logs and prints any high-scoring matches >= fuzzy_threshold.
    """
    if not fuzzy_words:
        return

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()

        for line_num, line in enumerate(lines, start=1):
            for fw in fuzzy_words:
                score = fuzz.partial_ratio(fw.lower(), line.lower())
                if score >= fuzzy_threshold:
                    log_message(
                        f"[bold magenta]Fuzzy match in {file_path}[/bold magenta]: "
                        f"'{fw}' (score={score}, line={line_num})"
                    )
    except Exception as e:
        error_message(f"Failed to perform fuzzy search in {file_path}: {e}")

# --- NEW ---
def compute_file_hash(file_path: str, hash_algo: str = "md5") -> str:
    """
    Compute the hash (MD5 by default) of a file's content.
    Return the hexadecimal digest.
    """
    try:
        h = hashlib.new(hash_algo)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        error_message(f"Failed to compute hash for {file_path}: {e}")
        return ""

# =====================
# Metadata Extraction
# =====================
def extract_file_metadata(file_path: str, do_hash: bool = False) -> dict:
    """
    Extract basic metadata for the given file: size, creation time, modification time.
    If do_hash is True, also compute the file's hash (MD5).
    Returns a dictionary with this information.
    """
    try:
        stat_info = os.stat(file_path)
        metadata = {
            "file_path": file_path,
            "size": stat_info.st_size,
            "creation_time": time.ctime(stat_info.st_ctime),
            "modification_time": time.ctime(stat_info.st_mtime)
        }
        if do_hash:
            metadata["hash"] = compute_file_hash(file_path, "md5")
        return metadata
    except Exception as e:
        error_message(f"Failed to extract metadata for file {file_path}: {e}")
        return {}

# =====================
# Single-file Download
# =====================
def download_file(
    conn: SMBConnection,
    share_name: str,
    remote_file_path: str,
    local_file_path: str,
    bar=None,
    read_juicy_files: bool = False,
    regex_pattern: str = "",
    metadata_extraction: bool = False,
    fuzzy_words: list[str] = None,
    fuzzy_threshold: int = 80,
    db_conn: sqlite3.Connection = None,
    hidden_read: bool = False  # --- NEW ---
):
    """
    Downloads a single file from SMB to local.
    Applies the same logic of:
       - Checking DB
       - Extracting metadata
       - Regex / Fuzzy searches
       - Prompt to read content if needed
       - Optionally hidden-read content if 'hidden_read' is enabled
    """
    if fuzzy_words is None:
        fuzzy_words = []

    try:
        attrs = conn.getAttributes(share_name, remote_file_path)
        last_write_time = attrs.last_write_time or 0
    except Exception as e:
        error_message(f"Could not get file attributes for '{remote_file_path}': {e}")
        return

    if db_conn and is_already_downloaded(db_conn, share_name, remote_file_path, last_write_time):
        if os.path.exists(local_file_path):
            log_message(f"Skipping (already downloaded): {remote_file_path}")
            if bar:
                bar()
            return
        else:
            remove_downloaded_file(db_conn, share_name, remote_file_path, last_write_time)
            log_message(f"Local file missing. Re-downloading: {remote_file_path}")

    try:
        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
        with open(local_file_path, 'wb') as local_file:
            conn.retrieveFile(share_name, remote_file_path, local_file)
        log_message(f"Downloaded single file: [cyan]{local_file_path}[/cyan]")
        if bar:
            bar()
    except Exception as e:
        error_message(f"Error downloading file '{remote_file_path}': {e}")
        return
    
    if db_conn:
        record_downloaded_file(db_conn, share_name, remote_file_path, local_file_path, last_write_time)

    # If we are extracting metadata, do it (including file hash).
    if metadata_extraction:
        file_metadata = extract_file_metadata(local_file_path, do_hash=True)
        if file_metadata:
            downloaded_metadata.append(file_metadata)

    # If read_juicy_files is True, prompt user to read.
    if read_juicy_files and local_file_path.lower().endswith(JUICY_EXTENSIONS):
        read_file_content(local_file_path)

    # --- NEW ---
    # If hidden_read is True and extension is juicy, read content silently
    if hidden_read and local_file_path.lower().endswith(JUICY_EXTENSIONS):
        hidden_read_file_content(local_file_path)

    # Regex search
    if regex_pattern:
        search_for_keywords(local_file_path, regex_pattern)

    # Fuzzy search
    if fuzzy_words:
        fuzzy_search_in_file(local_file_path, fuzzy_words, fuzzy_threshold)

    downloaded_files.append(local_file_path)

# =====================
# Recursive Download
# =====================
def download_files(
    conn: SMBConnection,
    share_name: str,
    remote_path: str,
    local_path: str,
    bar=None,
    read_juicy_files: bool = False,
    regex_pattern: str = "",
    metadata_extraction: bool = False,
    fuzzy_words: list[str] = None,
    fuzzy_threshold: int = 80,
    db_conn: sqlite3.Connection = None,
    hidden_read: bool = False  # --- NEW ---
) -> None:
    """
    Recursively downloads files from the specified SMB share and path.
    - If 'read_juicy_files' is True, prompt to read files with JUICY_EXTENSIONS.
    - If 'regex_pattern' is not empty, perform a regex search in each downloaded file.
    - If 'metadata_extraction' is True, extract basic metadata (including file hash).
    - If 'fuzzy_words' is not empty, do a fuzzy search with 'fuzzy_threshold' as min score.
    - 'db_conn' is an SQLite connection for persistence.
    - If 'hidden_read' is True, we silently read content of juicy extensions and store it in JSON.
    
    This function assumes that 'remote_path' is a directory.
    For single-file download, use 'download_file()' instead.
    """
    if fuzzy_words is None:
        fuzzy_words = []

    try:
        if not os.path.exists(local_path):
            os.makedirs(local_path, exist_ok=True)

        files = conn.listPath(share_name, remote_path)
        for file in files:
            if file.isDirectory:
                if file.filename not in ['.', '..']:
                    nested_remote = os.path.join(remote_path, file.filename)
                    nested_local = os.path.join(local_path, file.filename)
                    download_files(
                        conn,
                        share_name,
                        nested_remote,
                        nested_local,
                        bar,
                        read_juicy_files,
                        regex_pattern,
                        metadata_extraction,
                        fuzzy_words,
                        fuzzy_threshold,
                        db_conn,
                        hidden_read
                    )
            else:
                remote_file_path = os.path.join(remote_path, file.filename)
                local_file_path = os.path.join(local_path, file.filename)
                download_file(
                    conn,
                    share_name,
                    remote_file_path,
                    local_file_path,
                    bar,
                    read_juicy_files,
                    regex_pattern,
                    metadata_extraction,
                    fuzzy_words,
                    fuzzy_threshold,
                    db_conn,
                    hidden_read  # --- NEW ---
                )

    except Exception as e:
        error_message(f"Error listing/downloading from: {remote_path} -> {e}")

# =====================
# JSON summaries
# =====================
def save_to_json() -> None:
    """
    Saves the list of all downloaded files to download_summary.json
    """
    with open("download_summary.json", "w") as f:
        json.dump(downloaded_files, f, indent=4)

def save_metadata_to_json() -> None:
    """
    Saves the metadata of downloaded files to metadata_summary.json
    """
    with open("metadata_summary.json", "w") as f:
        json.dump(downloaded_metadata, f, indent=4)

# --- NEW ---
def save_hidden_read_to_json() -> None:
    """
    Saves the hidden-read contents of juicy files
    to a separate JSON, named with a datetime stamp.
    """
    if not hidden_read_data:
        return  # nothing to save
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"hidden_read_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(hidden_read_data, f, indent=4)
    log_message(f"Hidden read content saved to {filename}")

# =====================
# Counting files
# =====================
def count_files(
    conn: SMBConnection,
    share_name: str,
    remote_path: str,
    total_files: list[int]
) -> None:
    """
    Recursively counts the total number of files in a given path.
    'total_files' is a list with a single int item (a trick to manipulate by reference).
    """
    files = conn.listPath(share_name, remote_path)
    for file in files:
        if file.isDirectory:
            if file.filename not in ['.', '..']:
                child_path = os.path.join(remote_path, file.filename)
                count_files(conn, share_name, child_path, total_files)
        else:
            total_files[0] += 1

# =====================
# Checking share permissions
# =====================
def check_share_permissions(conn: SMBConnection, share_name: str) -> tuple[bool, bool]:
    """
    Checks if a share is readable (can_read) and writable (can_write).
    Try `listPath(share_name, "/")` first; if it fails, try `listPath(share_name, "")`.  
    If both fail due to "Access Denied," we conclude `can_read = False`.  
    If they fail for any other reason, it might not be a permissions issue, so we could still consider it as `True`.  
    Then, if `can_read` is True, we test `can_write` by creating and deleting a test directory.
    """
    can_read = False
    can_write = False

    test_roots = ["/", ""]

    for test_root in test_roots:
        try:
            conn.listPath(share_name, test_root)
            can_read = True
            break
        except Exception as e:
            pass

    if can_read:
        test_dir = "test_dir_" + str(int(time.time()))
        try:
            conn.createDirectory(share_name, test_dir)
            can_write = True
            conn.deleteDirectory(share_name, test_dir)
        except Exception:
            pass

    return (can_read, can_write)

# =====================
# Building and showing tree
# =====================
def build_file_tree(
    conn: SMBConnection, 
    share_name: str, 
    remote_path: str = ""
) -> dict:
    """
    Recursively builds a tree structure in a dict:
    {
      "name": <folder/file name>,
      "path": <SMB absolute path>,
      "isDirectory": bool,
      "children": []
    }
    """
    tree = {
        "name": remote_path if remote_path else "/",
        "path": remote_path,
        "isDirectory": True,
        "children": []
    }
    try:
        entries = conn.listPath(share_name, remote_path)
        for entry in entries:
            if entry.filename in [".", ".."]:
                continue
            
            child_path = os.path.join(remote_path, entry.filename)
            if entry.isDirectory:
                subtree = build_file_tree(conn, share_name, child_path)
                tree["children"].append(subtree)
            else:
                tree["children"].append({
                    "name": entry.filename,
                    "path": child_path,
                    "isDirectory": False,
                    "children": []
                })
    except Exception as e:
        error_message(f"Error building tree at {remote_path}: {e}")
    return tree

def print_tree(node: dict, prefix: str = "") -> None:
    """
    Prints the structure in a simple ASCII style.
    """
    if node["path"]:
        if node["isDirectory"]:
            console.print(f"{prefix}└── [bold]{node['name']}[/bold]")
        else:
            console.print(f"{prefix}└── {node['name']}")

    if node["isDirectory"]:
        new_prefix = prefix + "    "
        for i, child in enumerate(node["children"]):
            if i < len(node["children"]) - 1:
                print_tree(child, new_prefix.replace("└──", "├──"))
            else:
                print_tree(child, new_prefix)

def flatten_file_tree(node: dict) -> list:
    """
    Returns a list of (name, path, isDirectory) from the recursive structure.
    """
    results = []
    if node["path"]:
        results.append((node["name"], node["path"], node["isDirectory"]))
    for child in node["children"]:
        results.extend(flatten_file_tree(child))
    return results

# =====================
# Main
# =====================
if __name__ == "__main__":
    console.print(ASCII_ART)

    parser = ArgumentParser(
        prog="smbspider.py",
        usage="%(prog)s [-h] --ip IP [--share SHARE] [--username USERNAME] [--password PASSWORD] "
              "[--domain DOMAIN] [--port PORT] [--remote_path REMOTE_PATH] [--local_path LOCAL_PATH] "
              "[--read] [--regex-search REGEX_SEARCH] [--fuzzy-search FUZZY_SEARCH] "
              "[--fuzzy-threshold FUZZY_THRESHOLD] [--tree-interactive] [--metadata] [--loglevel LOGLEVEL] [--hidden-read]",
        description="SMB Spider"
    )

    parser.add_argument("--ip", required=True, help="SMB server IP address")
    parser.add_argument("--share", default="", help="SMB share name (optional). If not specified, enumerates shares")
    parser.add_argument("--username", default="", help="SMB username (optional)")
    parser.add_argument("--password", default="", help="SMB password (optional)")
    parser.add_argument("--domain", default="", help="SMB domain (optional)")
    parser.add_argument("--port", type=int, default=445, help="SMB server port (default: 445)")
    parser.add_argument("--remote_path", default="", help="Initial directory on the SMB share")
    parser.add_argument("--local_path", default="./smb_downloads", help="Directory to save downloaded files")
    parser.add_argument("--read", action="store_true", help="Read 'juicy' files after downloading (interactive prompt)")
    parser.add_argument("--regex-search", default="",
                        help="Regex pattern(s) to search in downloaded files (e.g. 'password|credential|secret')")
    parser.add_argument("--fuzzy-search", default="",
                        help="Path to a file containing words (one per line) to fuzzy-search in downloaded files")
    parser.add_argument("--fuzzy-threshold", type=int, default=80,
                        help="Minimum fuzzy match ratio (0-100). Default=80")
    parser.add_argument("--tree-interactive", action="store_true",
                        help="If set, show a tree preview and allow interactive selective download")
    parser.add_argument("--metadata", action="store_true",
                        help="Extract basic metadata from each downloaded file (also computes file hash)")
    parser.add_argument("--loglevel", default="INFO",
                        help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default=INFO")
    parser.add_argument("--hidden-read", action="store_true",
                        help="Silently read all juicy files and store their contents in a separate JSON file")

    args = parser.parse_args()

    logging.basicConfig(
        filename="smb_spider.log",
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    set_log_level(args.loglevel)

    db_conn = init_database()

    fuzzy_words = []
    if args.fuzzy_search:
        try:
            with open(args.fuzzy_search, "r", encoding="utf-8") as fw_file:
                fuzzy_words = [line.strip() for line in fw_file if line.strip()]
            log_message(f"Loaded [bold]{len(fuzzy_words)}[/bold] fuzzy search word(s) from {args.fuzzy_search}.")
        except Exception as e:
            error_message(f"Could not load fuzzy search words from {args.fuzzy_search}: {e}")

    conn = None

    try:
        log_message("Connecting to SMB server...")

        temp_share_name = args.share if args.share else "IPC$"
        conn = connect_with_retries(
            args.ip,
            temp_share_name,
            args.username,
            args.password,
            args.domain,
            args.port
        )
        log_message("Connected successfully.")

        selected_shares = []
        if not args.share:
            log_message("No share specified. Enumerating accessible shares...")
            all_shares = conn.listShares()

            candidate_shares = []
            for s in all_shares:
                can_read, can_write = check_share_permissions(conn, s.name)
                if can_read:
                    rw_status = "READ/WRITE" if can_write else "READ ONLY"
                    candidate_shares.append({"name": s.name, "rw": rw_status})

            if not candidate_shares:
                error_message("No accessible shares found with read permissions.")
                exit(1)

            choices_for_questionary = [
                questionary.Choice(title=f"{share['name']} ({share['rw']})", value=share['name'])
                for share in candidate_shares
            ]
            choices_for_questionary.append(
                questionary.Choice(
                    title="Exit (quit without spidering)",
                    value="exit"
                )
            )

            answer = questionary.checkbox(
                "Select the shares you want to spider:",
                choices=choices_for_questionary
            ).ask()

            if not answer or "exit" in answer:
                error_message("No valid shares selected. Exiting.")
                exit(1)

            selected_shares = answer
        else:
            selected_shares = [args.share]

        for share in selected_shares:
            if args.tree_interactive:
                log_message(f"Building file structure for share '[yellow]{share}[/yellow]'...")
                tree = build_file_tree(conn, share, args.remote_path)
                
                console.print(f"\n[bold magenta]Preview of share '{share}'[/bold magenta]:")
                print_tree(tree)
                console.print("\n")

                file_list = flatten_file_tree(tree)
                if not file_list:
                    error_message("No files or directories found in this share/path.")
                    continue

                choices_for_questionary = []
                for (name, path, is_dir) in file_list:
                    desc = "(Dir)" if is_dir else "(File)"
                    choices_for_questionary.append(
                        questionary.Choice(
                            title=f"{desc} {path}", 
                            value=(path, is_dir)
                        )
                    )
                choices_for_questionary.append(
                    questionary.Choice(title="Skip downloading this share", value=None)
                )

                selected_paths = questionary.checkbox(
                    f"Select the directories/files you want to download from share '{share}':",
                    choices=choices_for_questionary
                ).ask()

                if not selected_paths or all(sp is None for sp in selected_paths):
                    log_message(f"No items selected for share '{share}'. Skipping.")
                    continue

                total_to_download = [0]
                for (chosen_path, is_dir) in selected_paths:
                    if chosen_path is None:
                        continue
                    if is_dir:
                        count_files(conn, share, chosen_path, total_to_download)
                    else:
                        total_to_download[0] += 1

                log_message(f"Found {total_to_download[0]} total file(s) to download in share: {share}")

                with alive_bar(total_to_download[0], title=f'Downloading from {share}', bar='blocks') as bar:
                    for (chosen_path, is_dir) in selected_paths:
                        if chosen_path is None:
                            continue
                        if is_dir:
                            download_files(
                                conn,
                                share,
                                chosen_path,
                                args.local_path,
                                bar,
                                args.read,
                                args.regex_search,
                                args.metadata,
                                fuzzy_words,
                                args.fuzzy_threshold,
                                db_conn,
                                hidden_read=args.hidden_read  # --- pass it here
                            )
                        else:
                            local_file_path = os.path.join(args.local_path, os.path.basename(chosen_path))
                            download_file(
                                conn,
                                share,
                                chosen_path,
                                local_file_path,
                                bar,
                                args.read,
                                args.regex_search,
                                args.metadata,
                                fuzzy_words,
                                args.fuzzy_threshold,
                                db_conn,
                                hidden_read=args.hidden_read  # --- pass it here
                            )

                log_message(f"Download complete for share '{share}'.")

            else:
                log_message(f"Starting download from share '[yellow]{share}[/yellow]' (full, no --tree-interactive)...")
                total_files = [0]
                count_files(conn, share, args.remote_path, total_files)
                log_message(f"Found {total_files[0]} total file(s) to process in share: {share}")

                with alive_bar(total_files[0], title=f'Downloading files from {share}', bar='blocks') as bar:
                    download_files(
                        conn,
                        share,
                        args.remote_path,
                        args.local_path,
                        bar,
                        args.read,
                        args.regex_search,
                        args.metadata,
                        fuzzy_words,
                        args.fuzzy_threshold,
                        db_conn,
                        hidden_read=args.hidden_read  # --- pass it here
                    )

                log_message(f"Download complete for share '{share}'.")

    except Exception as e:
        error_message(f"Fatal error: {e}")

    finally:
        if conn:
            log_message("Closing SMB connection.")
            conn.close()
        if db_conn:
            db_conn.close()
            log_message("Closed local SQLite database connection.")

        # Regular summary
        save_to_json()
        log_message("Summary saved to download_summary.json.")

        if args.metadata:
            save_metadata_to_json()
            log_message("Metadata saved to metadata_summary.json.")

        # --- NEW ---
        if args.hidden_read:
            save_hidden_read_to_json()
