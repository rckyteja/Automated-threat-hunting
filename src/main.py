import re
import pandas as pd
import os

# Define the log file path (Update this if using a different log file)
LOG_FILE_PATH = "/var/log/auth.log"

# Output report path
OUTPUT_REPORT = "../data/threat_report.csv"

def parse_logs(file_path):
    """Parse the log file and extract relevant information."""
    if not os.path.exists(file_path):
        print(f"Log file not found: {file_path}")
        return []

    suspicious_activities = []
    with open(file_path, 'r') as file:
        for line in file:
            # Example: Detect failed login attempts
            if "Failed password" in line:
                suspicious_activities.append(line.strip())
    return suspicious_activities

def save_to_csv(data, output_path):
    """Save parsed data to a CSV file."""
    if not data:
        print("No suspicious activities detected.")
        return
    
    df = pd.DataFrame(data, columns=["Log Entry"])
    df.to_csv(output_path, index=False)
    print(f"Threat report saved to {output_path}")

def main():
    print("Parsing logs...")
    suspicious_logs = parse_logs(LOG_FILE_PATH)
    save_to_csv(suspicious_logs, OUTPUT_REPORT)

if __name__ == "__main__":
    main()
