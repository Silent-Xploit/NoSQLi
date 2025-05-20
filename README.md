# NoSQLi

A powerful Go-based NoSQL injection vulnerability scanner that automatically detects and tests for NoSQL injection vulnerabilities across multiple database types. Built with automation and ease of use in mind.

## Features

- 🔍 Automatic NoSQL database type detection
- 🎯 Support for multiple NoSQL databases (MongoDB, CouchDB, Elasticsearch, Firebase)
- 📝 Custom payload management via external JSON files
- 🚀 Dynamic injection strategies for both GET and POST requests
- 📊 Detailed JSON reports
- 🎨 Colored terminal output
- 🔒 Authentication support via headers and cookies

## Installation

```bash
# Install directly using go
go install github.com/Silent-Xploit/NoSQLi@latest

# Or clone and build manually
git clone https://github.com/Silent-Xploit/NoSQLi.git
cd NoSQLi
go build
```

## Usage

Basic usage:

```bash
# Simple scan
NoSQLi --url "https://target.com/api/login" --data '{"username":"admin","password":"test123"}'
```

Full options:

```bash
python nosqli_scanner.py \
  --url https://target.com/api/login \
  --method POST \
  --headers '{"Authorization": "Bearer token"}' \
  --cookies "session=abc123" \
  --data '{"username":"admin","password":"test123"}' \
  --payloads payloads/ \
  --db-type mongodb
```

## Arguments

- `--url`: Target endpoint URL (required)
- `--method`: HTTP method (GET or POST) (required)
- `--headers`: Custom headers as JSON string
- `--cookies`: Raw cookie string
- `--data`: JSON body for POST requests
- `--payloads`: Path to payload directory (required)
- `--db-type`: Force specific database type (optional)

## Payload Files

Payload files are stored in the `payloads/` directory:
- `mongo.json`: MongoDB-specific payloads
- `couchdb.json`: CouchDB-specific payloads
- `elasticsearch.json`: Elasticsearch-specific payloads
- `firebase.json`: Firebase-specific payloads

## Output

The tool generates a JSON report containing:
- Scan information (timestamp, target, etc.)
- Detected vulnerabilities
- Error logs
- Raw test results

## Example Report

```json
{
  "scan_info": {
    "url": "https://target.com/login",
    "method": "POST",
    "detected_db": "MongoDB",
    "timestamp": "2025-05-20 10:00:00",
    "total_tests": 50,
    "vulnerable_count": 2
  },
  "vulnerabilities": [
    {
      "vulnerable": true,
      "payload": {"$ne": null},
      "parameter": "password",
      "category": "auth_bypass",
      "reason": "Authentication bypass detected"
    }
  ]
}
```

## Security Note

This tool is for educational and security testing purposes only. Always obtain proper authorization before testing any systems you don't own.

## License

MIT License
