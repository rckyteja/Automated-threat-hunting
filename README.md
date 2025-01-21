# Automated Threat Hunting
A Python-based script to identify threats in system logs by analyzing failed login attempts and detecting suspicious IP activity.

## Features
- Parses system logs to extract suspicious activities, such as failed login attempts.
- Counts failed login attempts per IP address.
- Identifies suspicious IPs with activity above a configurable threshold.
- Generates two reports:
  - `threat_report.csv`: Logs of suspicious activities.
  - `ip_report.csv`: Summary of failed login attempts by IP.

## How to Use
1. Place the log file (e.g., `auth.log`) in the `data` directory.
2. Update the log file path in `src/main.py`:
   ```python
   LOG_FILE_PATH = "/path/to/your/logfile.log"
