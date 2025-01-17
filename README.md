# ![smbspider logo](https://dcollao.pages.dev/images/smbspider_logo.png) smbspider

**SmbSpider** is a Python-powered SMB enumeration built to help you scour Windows shares for sensitive files, credentials, or metadata in a fast and efficient way.

## Description

This tool performs recursive enumeration of SMB shares, helping you discover and download files, search for specific keywords (regex or fuzzy matches), and optionally read “juicy” file contents on the fly.

**smbspider** supports authentication using cleartext credentials (username/password) or domain credentials, and it records previously downloaded files in an SQLite database to avoid re-downloading. It also offers an interactive tree browsing mode to let you selectively grab only what you need.

It can operate without SMB encryption (though it's not recommended) and may be tunneled through a SOCKS proxy if configured at the system or networking level. This flexibility makes **smbspider** a convenient component for security assessments or general SMB share enumeration. 

## Simple usage

```bash
python smbspider.py --ip 10.129.85.242 --share "Users" --username "rose" --password "KxEPkKe6R8su" --regex-search "password|secret" --read --fuzzy-search common.txt
```

