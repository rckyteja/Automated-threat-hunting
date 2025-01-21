import re
import pandas as pd
import os

# Define the log file path (using the sample log file)
LOG_FILE_PATH = "../data/sample_auth.log"

# Output report paths
LOG_FILE_PATH = "/home/kali/Projects/automated-threat-hunting/data/sample_auth.log"
OUTPUT_LOG_REPORT = "/home/kali/Projects/automated-threat-hunting/data/threat_report.csv"
OUTPUT_IP_REPORT = "/home/kali/Projects/automated-threat-hunting/data/ip_report.csv"

def parse_logs(file_path):
    """Parse the log file and extract relevant information."""
    if not os.path.exists(file_path):
        print(f"Log file not found: {file_path}")
        return [], {}

    suspicious_activities = []
    ip_counts = {}
    with open(file_path, 'r') as file:
        for line in file:
            if "Failed password" in line:
                suspicious_activities.append(line.strip())
                # Extract IP address using regex
                ip_match = re.search(r"from ([\d.]+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return suspicious_activities, ip_counts

def save_to_csv(data, output_path):
    """Save parsed data to a CSV file."""
    if not data:
        print(f"No data to save for {output_path}")
        return

    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"Report saved to {output_path}")

def main():
    print("Parsing logs...")
    suspicious_logs, ip_counts = parse_logs(LOG_FILE_PATH)
    
    # Save suspicious logs to CSV
    save_to_csv({"Log Entry": suspicious_logs}, OUTPUT_LOG_REPORT)

    # Save IP counts to a separate CSV
    ip_data = [{"IP Address": ip, "Failed Attempts": count} for ip, count in ip_counts.items()]
    save_to_csv(ip_data, OUTPUT_IP_REPORT)

    # Print IP counts in the terminal
    print("\nFailed login attempts by IP:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count} attempts")

if __name__ == "__main__":
    main()
