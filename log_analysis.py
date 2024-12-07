import re
import csv
from collections import Counter, defaultdict

def parse_log(log_lines):
    """
    Parses log lines to extract IP addresses, endpoints, and HTTP statuses.
    Returns a list of tuples containing (IP, endpoint, status).
    """
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(GET|POST|PUT|DELETE) (?P<endpoint>[^\s]+).*" (?P<status>\d{3})')
    parsed_logs = []

    for line in log_lines:
        match = log_pattern.search(line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint")
            status = match.group("status")
            parsed_logs.append((ip, endpoint, status))

    return parsed_logs

def analyze_logs(parsed_logs):
    """
    Analyzes parsed logs to calculate:
    1. Total requests per IP.
    2. The most accessed endpoint.
    3. Suspicious activity (multiple 4xx/5xx status codes).
    """
    ip_counter = Counter()
    endpoint_counter = Counter()
    error_tracker = defaultdict(list)

    for ip, endpoint, status in parsed_logs:
        ip_counter[ip] += 1
        endpoint_counter[endpoint] += 1
        if status.startswith('4') or status.startswith('5'):
            error_tracker[ip].append(status)

    # Find most accessed endpoint
    most_accessed_endpoint = endpoint_counter.most_common(1)

    # Detect suspicious activity
    suspicious_activity = {ip: errors for ip, errors in error_tracker.items() if len(errors) > 3}

    return ip_counter, most_accessed_endpoint, suspicious_activity

def save_results_to_csv(ip_counter, most_accessed_endpoint, suspicious_activity, output_file):
    """
    Saves analysis results to a CSV file.
    """
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counter.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line for separation

        # Most accessed endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0][0], most_accessed_endpoint[0][1]])

        writer.writerow([])  # Blank line for separation

        # Suspicious activity
        writer.writerow(["Suspicious IP", "Error Codes"])
        for ip, errors in suspicious_activity.items():
            writer.writerow([ip, ", ".join(errors)])

def main():
    # Log file name
    log_file = "sample.log"
    output_file = "log_analysis_results.csv"

    try:
        # Read log file
        with open(log_file, 'r') as file:
            log_lines = file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
        return

    # Parse the log lines
    parsed_logs = parse_log(log_lines)

    # Analyze the logs
    ip_counter, most_accessed_endpoint, suspicious_activity = analyze_logs(parsed_logs)

    # Display results in the terminal
    print("IP Request Counts:")
    for ip, count in ip_counter.items():
        print(f"{ip}: {count}")

    print("\nMost Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0][0]}: {most_accessed_endpoint[0][1]} accesses")

    print("\nSuspicious Activity:")
    for ip, errors in suspicious_activity.items():
        print(f"{ip}: {', '.join(errors)}")

    # Save results to CSV
    save_results_to_csv(ip_counter, most_accessed_endpoint, suspicious_activity, output_file)
    print(f"\nResults saved to '{output_file}'.")

if __name__ == "__main__":
    main()
