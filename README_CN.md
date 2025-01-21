English | [简体中文](./README_CN.md)

# ![smbspider logo](https://dcollao.pages.dev/images/smbspider_logo.png) SMBspider

**SMBspider** 是一个基于 Python 的 SMB 枚举工具，旨在帮助你快速、高效地在 Windows 共享文件中搜索敏感文件、凭据或元数据。

## 描述

此工具可以递归枚举 SMB 共享文件，帮助你发现和下载文件，按关键字（正则表达式或模糊匹配）搜索，并可选地实时读取“敏感”文件内容。

**SMBspider** 支持通过明文凭据（用户名/密码）或域凭据进行身份验证，并记录已下载的文件到 SQLite 数据库以避免重复下载。它还提供交互式的树状浏览模式，让你只选择需要的内容下载。

该工具可以在没有 SMB 加密的情况下运行（尽管不推荐），并可通过 SOCKS 代理进行隧道传输（如果在系统或网络级别配置了代理）。这些功能使 **SMBspider** 成为安全评估或一般 SMB 共享枚举的一个便捷组件。

---

## 演示
https://github.com/user-attachments/assets/e3f09d15-4d5d-48ca-bb8f-d285e29cbe99

---

## 用户指南

### 全局参数

```bash

   ▄▄▄▄▄   █▀▄▀█ ███      ▄▄▄▄▄   █ ▄▄  ▄█ ██▄   ▄███▄   █▄▄▄▄ 
  █     ▀▄ █ █ █ █  █    █     ▀▄ █   █ ██ █  █  █▀   ▀  █  ▄▀ 
▄  ▀▀▀▀▄   █ ▄ █ █ ▀ ▄ ▄  ▀▀▀▀▄   █▀▀▀  ██ █   █ ██▄▄    █▀▀▌  
 ▀▄▄▄▄▀    █   █ █  ▄▀  ▀▄▄▄▄▀    █     ▐█ █  █  █▄   ▄▀ █  █  
              █  ███               █     ▐ ███▀  ▀███▀     █   
             ▀                      ▀                     ▀   v1.4
diego.collao.albornoz@gmail.com | dcollao.pages.dev | @3ky_sec     

usage: smbspider.py [-h] --ip IP [--share SHARE] [--username USERNAME] [--password PASSWORD] [--domain DOMAIN] [--port PORT] [--remote_path REMOTE_PATH] [--local_path LOCAL_PATH] [--read] [--regex-search REGEX_SEARCH] [--fuzzy-search FUZZY_SEARCH] [--fuzzy-threshold FUZZY_THRESHOLD] [--tree-interactive] [--metadata] [--loglevel LOGLEVEL] [--hidden-read]

SMBspider

options:
  -h, --help            显示帮助信息并退出
  --ip IP               SMB 服务器 IP 地址
  --share SHARE         SMB 共享名称（可选）。如果未指定，将枚举共享
  --username USERNAME   SMB 用户名（可选）
  --password PASSWORD   SMB 密码（可选）
  --domain DOMAIN       SMB 域（可选）
  --port PORT           SMB 服务器端口（默认：445）
  --remote_path REMOTE_PATH
                        SMB 共享中的初始目录
  --local_path LOCAL_PATH
                        保存下载文件的目录
  --read                下载后读取“敏感”文件内容
  --regex-search REGEX_SEARCH
                        在下载文件中搜索的正则表达式模式（例如 'password|credential|secret'）
  --fuzzy-search FUZZY_SEARCH
                        包含单词（每行一个）的文件路径，用于模糊搜索下载文件中的内容
  --fuzzy-threshold FUZZY_THRESHOLD
                        最小模糊匹配比率（0-100）。默认值为 80
  --tree-interactive    如果设置，显示树状预览并允许交互式选择性下载
  --metadata            提取每个下载文件的基本元数据（还会计算文件哈希值）
  --loglevel LOGLEVEL   设置日志级别（DEBUG, INFO, WARNING, ERROR, CRITICAL）。默认值为 INFO
  --hidden-read         静默读取所有敏感文件，并将其内容存储在单独的 JSON 文件中
```

---

### 指定共享的枚举示例

#### 枚举特定共享
```bash
python smbspider.py --ip 10.129.180.104 --share "Users" --username "rose" --password "KxEPkKe6R8su"
```

#### 枚举特定共享并实时读取敏感文件
```bash
python smbspider.py --ip 10.129.180.104 --share "Users" --username "rose" --password "KxEPkKe6R8su" --read
```

#### 枚举特定共享并使用模糊搜索读取敏感文件
```bash
python smbspider.py --ip 10.129.180.104 --share "Users" --username "rose" --password "KxEPkKe6R8su" --fuzzy-search common.txt --read
```

#### 枚举特定共享并使用正则表达式搜索读取敏感文件
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --regex-search "password|secret" --read
```

#### 枚举特定共享并提取元数据
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --read --metadata
```

#### 枚举特定共享并静默读取文件
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --hidden-read --metadata
```

#### 枚举特定共享并从指定路径读取文件
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --remote_path "\Default\Appdata\Local\Microsoft\Windows\WinX\Group3\" --read
```

#### 枚举特定共享并将文件保存到自定义目录
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --share "Users" --remote_path "\Default\Appdata\Local\Microsoft\Windows\WinX\Group3" --local_path "Group_Downloads" --read
```

---

### 枚举所有共享的示例

#### 枚举所有共享
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su"
```

#### 枚举所有共享并实时读取敏感文件
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --read
```

#### 枚举所有共享并使用模糊搜索读取敏感文件
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --fuzzy-search common.txt --read
```

#### 枚举所有共享并使用正则表达式搜索读取敏感文件
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --regex-search "password|secret" --read
```

#### 枚举所有共享并使用交互式树状显示
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --read --tree-interactive
```

#### 枚举所有共享并提取元数据（包括哈希值）
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --read --metadata
```

#### 枚举所有共享并静默读取文件
```bash
python smbspider.py --ip 10.129.180.104 --username "rose" --password "KxEPkKe6R8su" --hidden-read --metadata
```