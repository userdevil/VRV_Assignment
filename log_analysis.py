import re
import csv
from collections import defaultdict

def parse_log_file(log_file_path):
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)  # Track all failed login attempts

    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_request_count[ip_address] += 1

            # Extract endpoint
            endpoint_match = re.search(r'"(GET|POST|PUT|DELETE) (.+?) HTTP', line)
            if endpoint_match:
                endpoint = endpoint_match.group(2)
                endpoint_access_count[endpoint] += 1

            # Detect failed login attempts
            if re.search(r'401|Invalid credentials', line, re.IGNORECASE):
                if ip_match:
                    ip_address = ip_match.group(1)
                    failed_login_attempts[ip_address] += 1

    return ip_request_count, endpoint_access_count, failed_login_attempts

def write_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file="log_analysis_results.csv"):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Most accessed endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)

        # Suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_file_path = input("Enter the path to the log file: ")
    ip_requests, endpoint_access, suspicious_ips = parse_log_file(log_file_path)

    # Most accessed endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1])

    # Display results
    print("\nRequests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Save to CSV
    write_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    main()
