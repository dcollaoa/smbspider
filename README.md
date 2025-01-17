# ![smbspider logo](https://dcollao.pages.dev/images/smbspider_logo.png) smbspider

**SmbSpider** is a Python-powered SMB enumeration built to help you scour Windows shares for sensitive files, credentials, or metadata in a fast and efficient way.

## Description

This tool can perform recursive enumeration of SMB shares to facilitate privilege escalation or intel gathering in a Windows environment. By leveraging valid credentials, it connects to SMB services on target hosts to discover and download files, search for sensitive information (via regex or fuzzy matching), and optionally read "juicy" file contents on the fly.

**smbspider** supports authentication using cleartext passwords (username/password) or domain credentials and stores a local record in SQLite to prevent duplicated downloads. It also supports interactive tree browsing to selectively grab only what you need.

Exchange of sensitive information without encrypted SMB (SMB signing/SMB encryption) is possible, though not recommended. You can also run this tool through a SOCKS proxy if configured at the system level or via tunneling tools.

It is designed to be a versatile component in red teaming or security assessments.

## Simple usage

```bash
python smbspider.py --ip 10.129.85.242 --share "Users" --username "rose" --password "KxEPkKe6R8su" --regex-search "password|secret" --read --fuzzy-search common.txt
```

