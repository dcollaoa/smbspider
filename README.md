# ![smbspider logo](https://dcollao.pages.dev/images/smbspider_logo.png) smbspider

**smbspider** is a Python-powered SMB enumeration built to help you scour Windows shares for sensitive files, credentials, or metadata in a fast and efficient way.

## Description

This tool performs recursive enumeration of SMB shares, helping you discover and download files, search for specific keywords (regex or fuzzy matches), and optionally read “juicy” file contents on the fly.

**smbspider** supports authentication using cleartext credentials (username/password) or domain credentials, and it records previously downloaded files in an SQLite database to avoid re-downloading. It also offers an interactive tree browsing mode to let you selectively grab only what you need.

It can operate without SMB encryption (though it's not recommended) and may be tunneled through a SOCKS proxy if configured at the system or networking level. This flexibility makes **smbspider** a convenient component for security assessments or general SMB share enumeration. 

---

## Demo

[![smbspider_demo](https://pub-526793ce32ed4b74b90d92d47d14ccc4.r2.dev/0121.gif)](https://pub-526793ce32ed4b74b90d92d47d14ccc4.r2.dev/smbspider_demo.mp4)

---

## User Guide

### Global Arguments

```bash

   ▄▄▄▄▄   █▀▄▀█ ███      ▄▄▄▄▄   █ ▄▄  ▄█ ██▄   ▄███▄   █▄▄▄▄ 
  █     ▀▄ █ █ █ █  █    █     ▀▄ █   █ ██ █  █  █▀   ▀  █  ▄▀ 
▄  ▀▀▀▀▄   █ ▄ █ █ ▀ ▄ ▄  ▀▀▀▀▄   █▀▀▀  ██ █   █ ██▄▄    █▀▀▌  
 ▀▄▄▄▄▀    █   █ █  ▄▀  ▀▄▄▄▄▀    █     ▐█ █  █  █▄   ▄▀ █  █  
              █  ███               █     ▐ ███▀  ▀███▀     █   
             ▀                      ▀                     ▀   v1.3 | @3ky_sec 

usage: smbspider.py [-h] --ip IP [--share SHARE] [--username USERNAME] [--password PASSWORD] [--domain DOMAIN] [--port PORT] [--remote_path REMOTE_PATH] [--local_path LOCAL_PATH] [--read] [--regex-search REGEX_SEARCH] [--fuzzy-search FUZZY_SEARCH] [--fuzzy-threshold FUZZY_THRESHOLD] [--tree-interactive] [--metadata] [--loglevel LOGLEVEL]

SMB Spider

options:
  -h, --help            show this help message and exit
  --ip IP               SMB server IP address
  --share SHARE         SMB share name (optional). If not specified, enumerates shares
  --username USERNAME   SMB username (optional)
  --password PASSWORD   SMB password (optional)
  --domain DOMAIN       SMB domain (optional)
  --port PORT           SMB server port (default: 445)
  --remote_path REMOTE_PATH
                        Initial directory on the SMB share
  --local_path LOCAL_PATH
                        Directory to save downloaded files
  --read                Read 'juicy' files after downloading
  --regex-search REGEX_SEARCH
                        Regex pattern(s) to search in downloaded files (e.g. 'password|credential|secret')
  --fuzzy-search FUZZY_SEARCH
                        Path to a file containing words (one per line) to fuzzy-search in downloaded files
  --fuzzy-threshold FUZZY_THRESHOLD
                        Minimum fuzzy match ratio (0-100). Default=80
  --tree-interactive    If set, show a tree preview and allow interactive selective download
  --metadata            Extract basic metadata from each downloaded file
  --loglevel LOGLEVEL   Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default=INFO
```

## Spidering Specific Share Examples

#### Basic Spidering on a Specific Share
```bash
python smbspider.py --ip 10.129.180.104 --share "Users" --username "rose" --password "KxEPkKe6R8su"
```

#### Spidering a Specific Share and Reading Juicy Files on the Fly
```bash
python smbspider.py --ip 10.129.180.104 --share "Users" --username "rose" --password "KxEPkKe6R8su" --read
```

#### Spidering a Specific Share with Fuzzy Search and Reading Juicy Files
```bash
python smbspider.py --ip 10.129.180.104 --share "Users" --username "rose" --password "KxEPkKe6R8su" --fuzzy-search common.txt --read
```

#### Spidering a Specific Share with Regex Search and Reading Juicy Files
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --regex-search "password|secret" --read 
```

#### Spidering a Specific Share with Metadata Extraction
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --read --metadata
```

#### Spidering a Specific Share and Reading Files from a Specific Path
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --remote_path "\Default\Appdata\Local\Microsoft\Windows\WinX\Group3\" --read
```

#### Spidering a Specific Share and Saving Files in a Custom Directory
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --remote_path "\Default\Appdata\Local\Microsoft\Windows\WinX\Group3" --local_path "Group_Downloads" --read
```

---

### Spidering All Shares Examples

#### Basic Spidering on All Shares
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su"
```

#### Spidering All Shares and Reading Juicy Files on the Fly
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --read
```

#### Spidering All Shares with Fuzzy Search and Reading Juicy Files
```bash
python smbspider.py --ip 10.129.180.104  --username "rose" --password "KxEPkKe6R8su" --fuzzy-search common.txt --read
```

#### Spidering All Shares with Regex Search and Reading Juicy Files
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --regex-search "password|secret" --read 
```

#### Spidering All Shares with Tree Interactive
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --read --tree-interactive
```

#### Spidering All Shares with Metadata Extraction
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --read --metadata
```

