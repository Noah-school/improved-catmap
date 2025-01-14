import json
import subprocess

def run_searchsploit(query):
    result = subprocess.run(['searchsploit', query, '-j'], capture_output=True, text=True)
    return json.loads(result.stdout)

def extract_queries(data):
    queries = set()
    for ip, details in data.items():
        scan_data = details.get('scan', {}).get(ip, {})
        vendor = scan_data.get('vendor', {})
        tcp_ports = scan_data.get('tcp', {})
        
        for mac, vendor_name in vendor.items():
            queries.add(vendor_name)
        
        for port, info in tcp_ports.items():
            queries.add(info.get('name', ''))
    
    return queries

def main():
    with open('/home/noah/python/input.json', 'r') as f:
        data = json.load(f)
    
    queries = extract_queries(data)
    searchsploit_results = {}
    
    for query in queries:
        if query:  # Ensure the query is not empty
            searchsploit_results[query] = run_searchsploit(query)
    
    with open('/home/noah/python/searchsploit_output.json', 'w') as f:
        json.dump(searchsploit_results, f, indent=4)

if __name__ == "__main__":
    main()