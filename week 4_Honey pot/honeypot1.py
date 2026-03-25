import socket
import threading
import sqlite3
import time
import os
import json
from datetime import datetime
import subprocess
import sys

if os.path.exists('honeypot.db'):
    try:
        os.remove('honeypot.db')
        print("Old database deleted")
    except:
        pass

conn = sqlite3.connect('honeypot.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    port INTEGER,
    service TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    attempts INTEGER DEFAULT 1
)
''')

cursor.execute('''
CREATE TABLE commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    command TEXT,
    service TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

cursor.execute('''
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    username TEXT,
    password TEXT,
    service TEXT,
    success BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()

attack_counts = {}
blocked_ips = set()

def log_connection(ip, port, service):
    try:
        cursor.execute('INSERT INTO connections (ip_address, port, service) VALUES (?, ?, ?)', 
                      (ip, port, service))
        conn.commit()
        
        if ip not in attack_counts:
            attack_counts[ip] = 0
        attack_counts[ip] += 1
        
        print(f"[{datetime.now()}] Connection from {ip}:{port} to {service}")
        
        if attack_counts[ip] > 10:
            blocked_ips.add(ip)
            print(f"[ALERT] IP {ip} blocked after {attack_counts[ip]} attempts")
            
    except Exception as e:
        print(f"Database error: {e}")

def log_command(ip, command, service):
    try:
        cursor.execute('INSERT INTO commands (ip_address, command, service) VALUES (?, ?, ?)', 
                      (ip, command, service))
        conn.commit()
        print(f"[{datetime.now()}] Command from {ip}: {command}")
    except Exception as e:
        print(f"Database error: {e}")

def log_login_attempt(ip, username, password, service, success):
    try:
        cursor.execute('INSERT INTO login_attempts (ip_address, username, password, service, success) VALUES (?, ?, ?, ?, ?)', 
                      (ip, username, password, service, success))
        conn.commit()
        status = "SUCCESS" if success else "FAILED"
        print(f"[{datetime.now()}] Login {status} from {ip}: {username}/{password}")
    except Exception as e:
        print(f"Database error: {e}")

def fake_ssh_server(port=2222):
    def handle_ssh_client(client_socket, client_address):
        ip = client_address[0]
        if ip in blocked_ips:
            client_socket.close()
            return
            
        log_connection(ip, port, "SSH")
        
        try:
            client_socket.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            
            for attempt in range(3):
                client_socket.send(b"login: ")
                username = client_socket.recv(1024).decode().strip()
                
                client_socket.send(b"password: ")
                password = client_socket.recv(1024).decode().strip()
                
                if username and password:
                    log_login_attempt(ip, username, password, "SSH", False)
                    
                if attempt < 2:
                    client_socket.send(b"Login incorrect\r\n")
                else:
                    client_socket.send(b"Too many login attempts\r\n")
                    
        except:
            pass
        finally:
            client_socket.close()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"SSH Honeypot listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_ssh_client, args=(client, addr))
            thread.daemon = True
            thread.start()
        except:
            break

def fake_ftp_server(port=2121):
    def handle_ftp_client(client_socket, client_address):
        ip = client_address[0]
        if ip in blocked_ips:
            client_socket.close()
            return
            
        log_connection(ip, port, "FTP")
        
        try:
            client_socket.send(b"220 Welcome to FTP Server\r\n")
            
            while True:
                data = client_socket.recv(1024).decode().strip()
                if not data:
                    break
                    
                log_command(ip, data, "FTP")
                
                if data.upper().startswith("USER"):
                    username = data.split(" ", 1)[1] if " " in data else ""
                    client_socket.send(b"331 Password required\r\n")
                elif data.upper().startswith("PASS"):
                    password = data.split(" ", 1)[1] if " " in data else ""
                    log_login_attempt(ip, username if 'username' in locals() else "", password, "FTP", False)
                    client_socket.send(b"530 Login incorrect\r\n")
                elif data.upper().startswith("QUIT"):
                    client_socket.send(b"221 Goodbye\r\n")
                    break
                else:
                    client_socket.send(b"500 Unknown command\r\n")
                    
        except:
            pass
        finally:
            client_socket.close()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"FTP Honeypot listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_ftp_client, args=(client, addr))
            thread.daemon = True
            thread.start()
        except:
            break

def fake_telnet_server(port=2323):
    def handle_telnet_client(client_socket, client_address):
        ip = client_address[0]
        if ip in blocked_ips:
            client_socket.close()
            return
            
        log_connection(ip, port, "TELNET")
        
        try:
            client_socket.send(b"Welcome to Telnet Server\r\nlogin: ")
            
            username = client_socket.recv(1024).decode().strip()
            client_socket.send(b"password: ")
            password = client_socket.recv(1024).decode().strip()
            
            if username and password:
                log_login_attempt(ip, username, password, "TELNET", False)
                
            client_socket.send(b"Login failed\r\n")
            
            while True:
                client_socket.send(b"$ ")
                command = client_socket.recv(1024).decode().strip()
                if not command:
                    break
                    
                log_command(ip, command, "TELNET")
                
                if command.lower() == "exit":
                    break
                else:
                    client_socket.send(b"Command not found\r\n")
                    
        except:
            pass
        finally:
            client_socket.close()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"TELNET Honeypot listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_telnet_client, args=(client, addr))
            thread.daemon = True
            thread.start()
        except:
            break

def fake_http_server(port=8080):
    def handle_http_client(client_socket, client_address):
        ip = client_address[0]
        if ip in blocked_ips:
            client_socket.close()
            return
            
        log_connection(ip, port, "HTTP")
        
        try:
            request = client_socket.recv(1024).decode()
            
            log_command(ip, request.split('\n')[0], "HTTP")
            
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            response += "<html><body><h1>Server Under Maintenance</h1></body></html>"
            
            client_socket.send(response.encode())
            
        except:
            pass
        finally:
            client_socket.close()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"HTTP Honeypot listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_http_client, args=(client, addr))
            thread.daemon = True
            thread.start()
        except:
            break

def show_attack_statistics():
    try:
        print("\n" + "="*60)
        print("HONEYPOT ATTACK STATISTICS")
        print("="*60)
        
        cursor.execute('SELECT service, COUNT(*) as count FROM connections GROUP BY service')
        service_stats = cursor.fetchall()
        
        if service_stats:
            print("\nConnections by Service:")
            for service, count in service_stats:
                print(f"  {service}: {count} connections")
        
        cursor.execute('SELECT ip_address, COUNT(*) as count FROM connections GROUP BY ip_address ORDER BY count DESC LIMIT 10')
        top_ips = cursor.fetchall()
        
        if top_ips:
            print("\nTop Attacking IPs:")
            for ip, count in top_ips:
                print(f"  {ip}: {count} attempts")
        
        cursor.execute('SELECT username, password, COUNT(*) as count FROM login_attempts GROUP BY username, password ORDER BY count DESC LIMIT 10')
        top_creds = cursor.fetchall()
        
        if top_creds:
            print("\nMost Tried Credentials:")
            for username, password, count in top_creds:
                print(f"  {username}/{password}: {count} attempts")
        
        cursor.execute('SELECT command, COUNT(*) as count FROM commands GROUP BY command ORDER BY count DESC LIMIT 10')
        top_commands = cursor.fetchall()
        
        if top_commands:
            print("\nMost Common Commands:")
            for command, count in top_commands:
                print(f"  {command[:50]}: {count} times")
        
        print(f"\nBlocked IPs: {len(blocked_ips)}")
        for ip in list(blocked_ips)[:10]:
            print(f"  {ip}")
            
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"Error showing statistics: {e}")

def monitor_attacks():
    while True:
        time.sleep(30)
        current_time = datetime.now()
        
        cursor.execute('SELECT ip_address, COUNT(*) as count FROM connections WHERE timestamp > datetime("now", "-1 minute") GROUP BY ip_address HAVING count > 5')
        recent_attackers = cursor.fetchall()
        
        for ip, count in recent_attackers:
            if ip not in blocked_ips:
                blocked_ips.add(ip)
                print(f"[ALERT] {current_time} - Rapid attacks detected from {ip} ({count} connections in 1 minute)")

def start_all_services():
    print("Starting Honeypot Server...")
    print("WARNING: This will simulate vulnerable services for educational purposes only")
    print()
    
    services = [
        (fake_ssh_server, 2222),
        (fake_ftp_server, 2121),
        (fake_telnet_server, 2323),
        (fake_http_server, 8080)
    ]
    
    threads = []
    
    for service_func, port in services:
        thread = threading.Thread(target=service_func, args=(port,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    monitor_thread = threading.Thread(target=monitor_attacks)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    print("\nAll honeypot services started!")
    print("SSH: port 2222")
    print("FTP: port 2121") 
    print("TELNET: port 2323")
    print("HTTP: port 8080")
    print("\nPress Ctrl+C to stop and show statistics")
    print("-" * 50)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping honeypot...")
        show_attack_statistics()
        
        print("Generating attack report...")
        
        cursor.execute('SELECT * FROM connections ORDER BY timestamp DESC')
        connections = cursor.fetchall()
        
        cursor.execute('SELECT * FROM login_attempts ORDER BY timestamp DESC') 
        logins = cursor.fetchall()
        
        cursor.execute('SELECT * FROM commands ORDER BY timestamp DESC')
        commands = cursor.fetchall()
        
        report = {
            "total_connections": len(connections),
            "total_login_attempts": len(logins),
            "total_commands": len(commands),
            "blocked_ips": list(blocked_ips),
            "report_time": str(datetime.now())
        }
        
        with open('honeypot_report.json', 'w') as f:
            json.dump(report, f, indent=2)
            
        print("Attack report saved to honeypot_report.json")

if __name__ == "__main__":
    try:
        start_all_services()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            conn.close()
            print("Database connection closed.")
        except:
            pass
        print("Honeypot stopped. Goodbye!")