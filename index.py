import re
from collections import defaultdict
import csv
from typing import Dict, List, Tuple

def parse_log_file(file_path: str) -> List[Dict[str, str]]:
     log_entries = []
     log_pattern = re.compile(
        r'(\d+\.\d+\.\d+\.\d+) .+ "(\w+) (/\w+).*" (\d+) \d+ ?(.+)?'
    )
     
     with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                log_entries.append({
                    'ip_address': match.group(1),
                    'method': match.group(2),
                    'endpoint': match.group(3),
                    'status_code': match.group(4),
                    'message': match.group(5) or ''
                })
    
     return log_entries


def count_requests_per_ip(log_entries: List[Dict[str, str]]) -> Dict[str, int]:
    """
    Count the number of requests for each IP address.
    
    Args:
        log_entries (List[Dict]): Parsed log entries
    
    Returns:
        Dictionary of IP addresses and their request counts
    """
    ip_request_counts = defaultdict(int)
    for entry in log_entries:
        ip_request_counts[entry['ip_address']] += 1
    
    return dict(sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True))

def find_most_accessed_endpoint(log_entries: List[Dict[str, str]]) -> Tuple[str, int]:
    """
    Find the most frequently accessed endpoint.
    
    Args:
        log_entries (List[Dict]): Parsed log entries
    
    Returns:
        Tuple of (most accessed endpoint, access count)
    """
    endpoint_counts = defaultdict(int)
    for entry in log_entries:
        endpoint_counts[entry['endpoint']] += 1
    
    return max(endpoint_counts.items(), key=lambda x: x[1])

def detect_suspicious_activity(log_entries: List[Dict[str, str]], threshold: int = 10) -> Dict[str, int]:
    """
    Detect potential brute force login attempts.
    
    Args:
        log_entries (List[Dict]): Parsed log entries
        threshold (int): Number of failed login attempts to flag as suspicious
    
    Returns:
        Dictionary of suspicious IP addresses and their failed login counts
    """
    failed_login_ips = defaultdict(int)
    for entry in log_entries:
        if entry['status_code'] == '401' or 'Invalid credentials' in entry['message']:
            failed_login_ips[entry['ip_address']] += 1
    
    return {ip: count for ip, count in failed_login_ips.items() if count >= threshold}

def save_results_to_csv(results: Dict, filename: str = 'VRV_log_analysis_results.csv'):
    """
    Save analysis results to a CSV file.
    
    Args:
        results (Dict): Dictionary containing different analysis results
        filename (str): Output CSV file name
    """
    with open(filename, 'w', newline='') as csvfile:
        # Requests per IP section
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['IP Analysis'])
        csvwriter.writerow(['IP Address', 'Request Count'])
        for ip, count in results['ip_requests'].items():
            csvwriter.writerow([ip, count])
        
        csvwriter.writerow([])  # Blank row for readability
        
        # Most Accessed Endpoint section
        csvwriter.writerow(['Most Accessed Endpoint'])
        csvwriter.writerow(['Endpoint', 'Access Count'])
        csvwriter.writerow([results['most_accessed_endpoint'][0], results['most_accessed_endpoint'][1]])
        
        csvwriter.writerow([])  # Blank row for readability
        
        # Suspicious Activity section
        csvwriter.writerow(['Suspicious Activity'])
        csvwriter.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in results['suspicious_ips'].items():
            csvwriter.writerow([ip, count])

def main(log_file_path: str):
    """
    Main function to perform log file analysis.
    
    Args:
        log_file_path (str): Path to the log file
    """
    # Parse log file
    log_entries = parse_log_file(log_file_path)
    
    # Perform analyses
    ip_requests = count_requests_per_ip(log_entries)
    most_accessed_endpoint = find_most_accessed_endpoint(log_entries)
    suspicious_ips = detect_suspicious_activity(log_entries)
    
    # Display results
    print("IP Request Counts:")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
    
    # Save results to CSV
    save_results_to_csv({
        'ip_requests': ip_requests,
        'most_accessed_endpoint': most_accessed_endpoint,
        'suspicious_ips': suspicious_ips
    })

if __name__ == "__main__":
    main('VRV_sample.log')