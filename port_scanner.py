import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

def resolve_domain(domain):
    """Resolves a domain name to an IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"Error: Unable to resolve domain '{domain}' to an IP address.")
        return None

def detect_http_version(ip, port):
    """Detects HTTP version by sending a HEAD request."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            response = s.recv(1024).decode()
            if response.startswith("HTTP/"):
                version = response.split("\r\n")[0]
                return version
    except Exception:
        return "Unknown HTTP version"

def detect_ssl_version(ip, port):
    """Detects SSL/TLS version by initiating a handshake."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=1) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssl_version = ssock.version()
                if ssl_version:
                    return f"SSL/TLS {ssl_version}"
                else:
                    return "Unknown SSL/TLS version"
    except ssl.SSLError as ssl_err:
        return f"SSL/TLS Error: {ssl_err}"
    except Exception as e:
        return f"Error: {e}"

def scan_port(ip, port):
    """Scans a single port and detects the service and version."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown service"
                
                version_info = ""
                if service == "http":
                    version_info = detect_http_version(ip, port)
                elif service == "https":
                    version_info = detect_ssl_version(ip, port)

                print(f"Port {port}: Open ({service}) {version_info}")
    except Exception:
        pass

def scan_ports(ip, start_port, end_port, max_threads=50):
    """Scans a range of ports using multithreading."""
    print(f"Scanning {ip} from port {start_port} to {end_port}...")
    with ThreadPoolExecutor(max_threads) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port)

def main():
    print("Python Port Scanner with Domain and Service Detection")
    print("=====================================================")
    
    # Get user input for domain or IP address
    target = input("Enter the domain or IP address to scan: ").strip()
    if not target:
        print("Error: Target cannot be empty!")
        return
    
    # Resolve domain to IP if necessary
    ip = resolve_domain(target) if not target.replace('.', '').isdigit() else target
    if not ip:
        return
    
    # Get user input for port range
    try:
        port_range = input("Enter the port range to scan (e.g., 20-80): ").strip()
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        print("Error: Invalid port range format! Use start-end (e.g., 20-80).")
        return
    
    # Perform the scan
    scan_ports(ip, start_port, end_port)

if __name__ == "__main__":
    main()
