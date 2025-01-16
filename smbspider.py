import os
import time
import json
import logging
import re
from argparse import ArgumentParser
from smb.SMBConnection import SMBConnection
from smb.base import NotConnectedError, SMBTimeout
from alive_progress import alive_bar
from colorama import Fore, Style
from rich.console import Console
import questionary

console = Console()

# We'll set up a global list to hold metadata if --metadata is enabled
downloaded_files = []
downloaded_metadata = []

ASCII_ART = """
[cyan]
   ▄▄▄▄▄   █▀▄▀█ ███      ▄▄▄▄▄   █ ▄▄  ▄█ ██▄   ▄███▄   █▄▄▄▄ 
  █     ▀▄ █ █ █ █  █    █     ▀▄ █   █ ██ █  █  █▀   ▀  █  ▄▀ 
▄  ▀▀▀▀▄   █ ▄ █ █ ▀ ▄ ▄  ▀▀▀▀▄   █▀▀▀  ██ █   █ ██▄▄    █▀▀▌  
 ▀▄▄▄▄▀    █   █ █  ▄▀  ▀▄▄▄▄▀    █     ▐█ █  █  █▄   ▄▀ █  █  
              █  ███               █     ▐ ███▀  ▀███▀     █   
             ▀                      ▀                     ▀[/cyan][purple]   v1.1 | @3ky_sec [/purple]
"""

# Put what extension you want to read
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
# SMB Connection
# =====================
def connect_to_smb(
    server_ip: str,
    share_name: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    port: int = 445 # default port
) -> SMBConnection:
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
# Read file content
# =====================
def read_file_content(file_path: str) -> None:
    """
    Prompt the user to decide if they want to display the file's content
    in the console.
    """
    try:
        console.print(
            f"[blue]Do you want to read the file {file_path}? (y/n):[/blue] ",
            end=""
        )
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


# =====================
# Search for Keywords
# =====================
def search_for_keywords(file_path: str, pattern: str) -> None:
    """
    Searches the downloaded file for certain keywords or patterns
    using regex. Prints any matches found and logs them.
    Example pattern: "password|credential|secret"
    """
    if not pattern:
        return  # Skip if pattern is empty

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            # Compile the regex pattern with case-insensitive match
            regex = re.compile(pattern, re.IGNORECASE)
            matches = regex.findall(content)
            if matches:
                # If any matches are found, highlight them
                unique_matches = set(matches)  # deduplicate
                log_message(
                    f"[bold yellow]Keyword(s) found in {file_path}:[/bold yellow] "
                    f"{', '.join(unique_matches)}"
                )
    except Exception as e:
        error_message(f"Failed to search in file {file_path}: {e}")


# =====================
# Metadata Extraction
# =====================
def extract_file_metadata(file_path: str) -> dict:
    """
    Extracts basic metadata for the given file: size, creation time, modification time.
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
        return metadata
    except Exception as e:
        error_message(f"Failed to extract metadata for file {file_path}: {e}")
        return {}


# =====================
# Download files
# =====================
def download_files(
    conn: SMBConnection,
    share_name: str,
    remote_path: str,
    local_path: str,
    bar=None,
    read_juicy_files: bool = False,
    search_pattern: str = "",
    metadata_extraction: bool = False
) -> None:
    """
    Recursively downloads files from the specified SMB share and path.
    If 'read_juicy_files' is True, the script will prompt to read
    JUICY_EXTENSIONS in the console.
    If 'search_pattern' is not empty, the script will perform a regex
    search on every downloaded file.
    If 'metadata_extraction' is True, extract basic file metadata and store it.
    """
    try:
        if not os.path.exists(local_path):
            os.makedirs(local_path)

        files = conn.listPath(share_name, remote_path)
        for file in files:
            if file.isDirectory:
                # Skip '.' and '..'
                if file.filename not in ['.', '..']:
                    download_files(
                        conn,
                        share_name,
                        os.path.join(remote_path, file.filename),
                        os.path.join(local_path, file.filename),
                        bar,
                        read_juicy_files,
                        search_pattern,
                        metadata_extraction
                    )
            else:
                local_file_path = os.path.join(local_path, file.filename)
                with open(local_file_path, 'wb') as local_file:
                    conn.retrieveFile(
                        share_name,
                        os.path.join(remote_path, file.filename),
                        local_file
                    )
                    log_message(f"Downloaded: [cyan]{local_file_path}[/cyan]")
                    downloaded_files.append(local_file_path)
                    if bar:
                        bar()

                # Metadata extraction
                if metadata_extraction:
                    file_metadata = extract_file_metadata(local_file_path)
                    if file_metadata:
                        downloaded_metadata.append(file_metadata)

                # If --read is enabled, prompt user to read the file if extension matches
                if read_juicy_files and file.filename.endswith(JUICY_EXTENSIONS):
                    read_file_content(local_file_path)

                # If --search is provided, search the file for the pattern
                if search_pattern:
                    search_for_keywords(local_file_path, search_pattern)

    except Exception as e:
        error_message(f"Error downloading {remote_path}: {e}")


def save_to_json() -> None:
    """
    Saves the list of all downloaded files to download_summary.json
    """
    with open("download_summary.json", "w") as f:
        json.dump(downloaded_files, f, indent=4)


def save_metadata_to_json() -> None:
    """
    Saves the metadata of all downloaded files to metadata_summary.json
    """
    with open("metadata_summary.json", "w") as f:
        json.dump(downloaded_metadata, f, indent=4)


def count_files(
    conn: SMBConnection,
    share_name: str,
    remote_path: str,
    total_files: list[int]
) -> None:
    """
    Recursively counts the total number of files in a given path.
    'total_files' is a single-element list used as a mutable counter.
    """
    files = conn.listPath(share_name, remote_path)
    for file in files:
        if file.isDirectory:
            if file.filename not in ['.', '..']:
                count_files(conn, share_name, os.path.join(remote_path, file.filename), total_files)
        else:
            total_files[0] += 1


def check_share_permissions(conn: SMBConnection, share_name: str) -> tuple[bool, bool]:
    """
    Checks if a share is readable (can_read) and writable (can_write)
    by attempting to list directory content and create/delete a test directory.
    Returns (can_read, can_write).
    """
    can_read = False
    can_write = False

    try:
        conn.listPath(share_name, "/")
        can_read = True
    except Exception:
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
# MAIN
# =====================
if __name__ == "__main__":
    console.print(ASCII_ART)

    parser = ArgumentParser(description="SMB Spider")
    parser.add_argument("--ip", required=True, help="SMB server IP address")
    parser.add_argument(
        "--share",
        default="",
        help="SMB share name (optional). If not specified, available shares will be enumerated"
    )
    parser.add_argument("--username", default="", help="SMB username (optional)")
    parser.add_argument("--password", default="", help="SMB password (optional)")
    parser.add_argument("--domain", default="", help="SMB domain (optional)")
    parser.add_argument("--port", type=int, default=445, help="SMB server port (default: 445)")
    parser.add_argument("--remote_path", default="", help="Initial directory on the SMB share")
    parser.add_argument("--local_path", default="./smb_downloads", help="Directory to save downloaded files")
    parser.add_argument("--read", action="store_true", help="Read juicy files after downloading (.txt, .pdf, etc.)")
    parser.add_argument(
        "--search",
        default="",
        help="Regex pattern(s) to search for in downloaded files (e.g. 'password|credential|secret')"
    )
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Extract basic metadata from each downloaded file and store it in metadata_summary.json"
    )
    parser.add_argument(
        "--loglevel",
        default="INFO",
        help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default is INFO"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        filename="smb_spider.log",
        level=logging.DEBUG,  # We'll override this below with set_log_level
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    # Override level with user choice
    set_log_level(args.loglevel)

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
            log_message(f"Starting download from share '[yellow]{share}[/yellow]'...")

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
                    args.search,
                    args.metadata
                )

            log_message(f"Download complete for share '{share}'.")

    except Exception as e:
        error_message(f"Fatal error: {e}")

    finally:
        if conn:
            log_message("Closing connection.")
            conn.close()

        save_to_json()
        log_message("Summary saved to download_summary.json.")

        if args.metadata:
            save_metadata_to_json()
            log_message("Metadata saved to metadata_summary.json.")

