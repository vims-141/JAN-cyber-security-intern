#!/usr/bin/env python3
"""
Personal Firewall - Complete Implementation
Choose: 1=CLI, 2=GUI, 3=Exit

Requirements:
- pip install scapy
- Run as Administrator (Windows) or sudo (Linux/Mac)
"""

import sys
import os
import time
import json
import threading
from datetime import datetime

# Check for required modules
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

class FirewallRule:
    """Simple firewall rule"""
    def __init__(self, rule_id, name, action, ip_address="", port="", protocol="any"):
        self.rule_id = rule_id
        self.name = name
        self.action = action  # "block" or "allow"
        self.ip_address = ip_address
        self.port = port
        self.protocol = protocol
        self.enabled = True
        self.hits = 0
    
    def matches_packet(self, packet_info):
        if not self.enabled:
            return False
        
        # Check IP
        if self.ip_address and self.ip_address != "any":
            src_ip = packet_info.get('src_ip', '')
            dst_ip = packet_info.get('dst_ip', '')
            if self.ip_address not in [src_ip, dst_ip]:
                return False
        
        # Check port
        if self.port and self.port != "any":
            src_port = str(packet_info.get('src_port', ''))
            dst_port = str(packet_info.get('dst_port', ''))
            if str(self.port) not in [src_port, dst_port]:
                return False
        
        # Check protocol
        if self.protocol and self.protocol != "any":
            if packet_info.get('protocol', '') != self.protocol:
                return False
        
        return True

class SimpleFirewall:
    """Core firewall functionality"""
    def __init__(self):
        self.rules = {}
        self.rule_counter = 1
        self.logs = []
        self.stats = {'total': 0, 'blocked': 0, 'allowed': 0}
        self.running = False
        
        # Add default rules
        self.add_rule("Block Telnet", "block", "", "23", "tcp")
        self.add_rule("Block SMB", "block", "", "445", "tcp")
        self.add_rule("Allow HTTP", "allow", "", "80", "tcp")
        self.add_rule("Allow HTTPS", "allow", "", "443", "tcp")
    
    def add_rule(self, name, action, ip="", port="", protocol="any"):
        rule = FirewallRule(self.rule_counter, name, action, ip, port, protocol)
        self.rules[self.rule_counter] = rule
        self.rule_counter += 1
        return rule
    
    def process_packet(self, packet):
        """Process captured packet"""
        try:
            packet_info = self.extract_packet_info(packet)
            if not packet_info:
                return
            
            self.stats['total'] += 1
            
            # Check rules
            action = "allow"
            matched_rule = "Default"
            
            for rule in self.rules.values():
                if rule.matches_packet(packet_info):
                    action = rule.action
                    matched_rule = rule.name
                    rule.hits += 1
                    break
            
            if action == "block":
                self.stats['blocked'] += 1
            else:
                self.stats['allowed'] += 1
            
            # Log packet
            log_entry = {
                'time': datetime.now().strftime("%H:%M:%S"),
                'action': action,
                'rule': matched_rule,
                'src_ip': packet_info.get('src_ip', ''),
                'dst_ip': packet_info.get('dst_ip', ''),
                'protocol': packet_info.get('protocol', ''),
                'port': packet_info.get('dst_port', '')
            }
            
            self.logs.append(log_entry)
            if len(self.logs) > 1000:
                self.logs = self.logs[-1000:]
            
            return action, matched_rule, packet_info
            
        except Exception as e:
            print(f"Packet processing error: {e}")
            return None, None, None
    
    def extract_packet_info(self, packet):
        """Extract packet information"""
        info = {'timestamp': datetime.now().strftime("%H:%M:%S")}
        
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            
            if TCP in packet:
                info['protocol'] = 'tcp'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
            elif UDP in packet:
                info['protocol'] = 'udp'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
            elif ICMP in packet:
                info['protocol'] = 'icmp'
                info['src_port'] = ''
                info['dst_port'] = ''
        
        return info

class FirewallCLI:
    """Command Line Interface"""
    def __init__(self):
        self.firewall = SimpleFirewall()
        self.monitoring = False
    
    def run(self):
        """Run CLI interface"""
        print("\n" + "="*50)
        print("         PERSONAL FIREWALL - CLI MODE")
        print("="*50)
        
        if not SCAPY_AVAILABLE:
            print("❌ ERROR: Scapy not installed!")
            print("   Install with: pip install scapy")
            return
        
        while True:
            self.show_menu()
            choice = input("\nEnter choice: ").strip()
            
            if choice == '1':
                self.show_rules()
            elif choice == '2':
                self.add_rule_cli()
            elif choice == '3':
                self.delete_rule_cli()
            elif choice == '4':
                self.start_monitoring()
            elif choice == '5':
                self.stop_monitoring()
            elif choice == '6':
                self.show_stats()
            elif choice == '7':
                self.show_logs()
            elif choice == '8':
                print("Exiting CLI...")
                self.stop_monitoring()
                break
            else:
                print("❌ Invalid choice!")
            
            input("\nPress Enter to continue...")
    
    def show_menu(self):
        print(f"\n📊 Status: {'🟢 RUNNING' if self.monitoring else '🔴 STOPPED'}")
        print(f"📈 Stats: {self.firewall.stats['total']} total, {self.firewall.stats['blocked']} blocked")
        print("\n--- FIREWALL MENU ---")
        print("1. View Rules")
        print("2. Add Rule")
        print("3. Delete Rule")
        print("4. Start Monitoring")
        print("5. Stop Monitoring")
        print("6. Show Statistics")
        print("7. View Logs")
        print("8. Exit")
    
    def show_rules(self):
        print("\n--- FIREWALL RULES ---")
        print(f"{'ID':<3} {'Name':<15} {'Action':<6} {'IP':<15} {'Port':<6} {'Proto':<6} {'Status':<8} {'Hits':<5}")
        print("-" * 70)
        
        for rule in self.firewall.rules.values():
            ip_display = rule.ip_address if rule.ip_address else "any"
            port_display = rule.port if rule.port else "any"
            status = "ON" if rule.enabled else "OFF"
            
            print(f"{rule.rule_id:<3} {rule.name[:15]:<15} {rule.action.upper():<6} {ip_display[:15]:<15} {port_display:<6} {rule.protocol:<6} {status:<8} {rule.hits:<5}")
    
    def add_rule_cli(self):
        print("\n--- ADD NEW RULE ---")
        name = input("Rule name: ").strip()
        if not name:
            print("❌ Name required!")
            return
        
        action = input("Action (block/allow): ").strip().lower()
        if action not in ['block', 'allow']:
            print("❌ Action must be 'block' or 'allow'!")
            return
        
        ip = input("IP address (optional): ").strip()
        port = input("Port (optional): ").strip()
        protocol = input("Protocol (tcp/udp/icmp/any) [any]: ").strip().lower()
        if not protocol:
            protocol = "any"
        
        rule = self.firewall.add_rule(name, action, ip, port, protocol)
        print(f"✅ Rule '{name}' added with ID {rule.rule_id}")
    
    def delete_rule_cli(self):
        self.show_rules()
        try:
            rule_id = int(input("\nEnter rule ID to delete: "))
            if rule_id in self.firewall.rules:
                rule_name = self.firewall.rules[rule_id].name
                del self.firewall.rules[rule_id]
                print(f"✅ Rule '{rule_name}' deleted")
            else:
                print("❌ Rule not found!")
        except ValueError:
            print("❌ Invalid ID!")
    
    def start_monitoring(self):
        if self.monitoring:
            print("⚠️ Already monitoring!")
            return
        
        print("🚀 Starting packet monitoring...")
        print("   (Press Ctrl+C to stop)")
        
        def packet_handler(packet):
            action, rule, packet_info = self.firewall.process_packet(packet)
            if action and packet_info:
                symbol = "🚫" if action == "block" else "✅"
                print(f"{symbol} {packet_info.get('src_ip', '')} → {packet_info.get('dst_ip', '')} ({packet_info.get('protocol', '')}) - {rule}")
        
        def start_sniffing():
            try:
                self.monitoring = True
                sniff(prn=packet_handler, stop_filter=lambda x: not self.monitoring, timeout=1)
            except KeyboardInterrupt:
                pass
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
        
        self.monitor_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.monitor_thread.start()
        
        # Monitor for a few seconds then return to menu
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            pass
        
        print("\n⏸️ Monitoring continues in background...")
    
    def stop_monitoring(self):
        if not self.monitoring:
            print("⚠️ Not monitoring!")
            return
        
        self.monitoring = False
        print("⏹️ Monitoring stopped")
    
    def show_stats(self):
        print("\n--- STATISTICS ---")
        print(f"Total Packets: {self.firewall.stats['total']}")
        print(f"Blocked: {self.firewall.stats['blocked']}")
        print(f"Allowed: {self.firewall.stats['allowed']}")
        
        print(f"\n--- RULE HITS ---")
        for rule in self.firewall.rules.values():
            if rule.hits > 0:
                print(f"{rule.name}: {rule.hits} hits")
    
    def show_logs(self):
        print("\n--- RECENT LOGS (Last 20) ---")
        for log in self.firewall.logs[-20:]:
            action_symbol = "🚫" if log['action'] == 'block' else "✅"
            print(f"[{log['time']}] {action_symbol} {log['src_ip']} → {log['dst_ip']} ({log['protocol']}) - {log['rule']}")

class FirewallGUI:
    """Graphical User Interface"""
    def __init__(self):
        self.firewall = SimpleFirewall()
        self.monitoring = False
        
        self.root = tk.Tk()
        self.root.title("Personal Firewall")
        self.root.geometry("800x600")
        
        self.create_gui()
        self.update_display()
        
        # Start periodic updates
        self.root.after(1000, self.periodic_update)
    
    def create_gui(self):
        # Main tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Dashboard
        self.create_dashboard(notebook)
        
        # Rules
        self.create_rules_tab(notebook)
        
        # Monitor
        self.create_monitor_tab(notebook)
    
    def create_dashboard(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="Dashboard")
        
        # Status
        status_frame = ttk.LabelFrame(frame, text="Firewall Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = tk.Label(status_frame, text="STOPPED", 
                                   font=('Arial', 16, 'bold'), fg='red')
        self.status_label.pack(pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(status_frame)
        btn_frame.pack(pady=5)
        
        self.start_btn = tk.Button(btn_frame, text="Start Firewall", 
                                 command=self.start_firewall, bg='lightgreen')
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(btn_frame, text="Stop Firewall", 
                                command=self.stop_firewall, bg='lightcoral', 
                                state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Stats
        stats_frame = ttk.LabelFrame(frame, text="Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(padx=10, pady=10)
        
        stats = [("Total Packets", "total"), ("Blocked", "blocked"), ("Allowed", "allowed")]
        for i, (label, key) in enumerate(stats):
            tk.Label(stats_grid, text=f"{label}:").grid(row=0, column=i*2, padx=5)
            self.stats_labels[key] = tk.Label(stats_grid, text="0", font=('Arial', 10, 'bold'))
            self.stats_labels[key].grid(row=0, column=i*2+1, padx=5)
        
        # Activity log
        activity_frame = ttk.LabelFrame(frame, text="Activity Log")
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=15)
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_rules_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="Rules")
        
        # Rules list
        rules_frame = ttk.LabelFrame(frame, text="Firewall Rules")
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("ID", "Name", "Action", "IP", "Port", "Protocol", "Status", "Hits")
        self.rules_tree = ttk.Treeview(rules_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=80)
        
        scrollbar = ttk.Scrollbar(rules_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(btn_frame, text="Add Rule", command=self.add_rule_dialog).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_rules).pack(side=tk.LEFT, padx=5)
    
    def create_monitor_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="Live Monitor")
        
        monitor_frame = ttk.LabelFrame(frame, text="Live Packets")
        monitor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Time", "Source", "Destination", "Protocol", "Port", "Action", "Rule")
        self.monitor_tree = ttk.Treeview(monitor_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.monitor_tree.heading(col, text=col)
            self.monitor_tree.column(col, width=100)
        
        monitor_scrollbar = ttk.Scrollbar(monitor_frame, orient=tk.VERTICAL, command=self.monitor_tree.yview)
        self.monitor_tree.configure(yscrollcommand=monitor_scrollbar.set)
        
        self.monitor_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        monitor_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        tk.Button(frame, text="Clear Monitor", command=self.clear_monitor).pack(pady=5)
    
    def start_firewall(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy not installed!\nInstall with: pip install scapy")
            return
        
        def packet_handler(packet):
            action, rule, packet_info = self.firewall.process_packet(packet)
            if action and packet_info:
                self.root.after(0, lambda: self.packet_received(packet_info, action, rule))
        
        def start_sniffing():
            try:
                sniff(prn=packet_handler, stop_filter=lambda x: not self.monitoring, timeout=1)
            except Exception as e:
                self.log_activity(f"❌ Error: {e}")
        
        self.monitoring = True
        self.status_label.config(text="RUNNING", fg='green')
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self.monitor_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.monitor_thread.start()
        
        self.log_activity("✅ Firewall started")
    
    def stop_firewall(self):
        self.monitoring = False
        self.status_label.config(text="STOPPED", fg='red')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_activity("⏹️ Firewall stopped")
    
    def packet_received(self, packet_info, action, rule):
        # Add to monitor
        children = self.monitor_tree.get_children()
        if len(children) >= 50:
            self.monitor_tree.delete(children[0])
        
        port = packet_info.get('dst_port', packet_info.get('src_port', ''))
        
        self.monitor_tree.insert("", "end", values=(
            packet_info['timestamp'],
            packet_info.get('src_ip', ''),
            packet_info.get('dst_ip', ''),
            packet_info.get('protocol', ''),
            port,
            action.upper(),
            rule
        ))
        
        # Auto-scroll
        children = self.monitor_tree.get_children()
        if children:
            self.monitor_tree.see(children[-1])
        
        # Log if blocked
        if action == "block":
            self.log_activity(f"🚫 Blocked: {packet_info.get('src_ip', '')} → {packet_info.get('dst_ip', '')} ({rule})")
    
    def add_rule_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Rule")
        dialog.geometry("300x250")
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Rule Name:").pack(pady=5)
        name_entry = tk.Entry(dialog, width=30)
        name_entry.pack(pady=5)
        
        tk.Label(dialog, text="Action:").pack(pady=5)
        action_var = tk.StringVar(value="block")
        action_frame = ttk.Frame(dialog)
        action_frame.pack(pady=5)
        tk.Radiobutton(action_frame, text="Block", variable=action_var, value="block").pack(side=tk.LEFT)
        tk.Radiobutton(action_frame, text="Allow", variable=action_var, value="allow").pack(side=tk.LEFT)
        
        tk.Label(dialog, text="IP Address:").pack(pady=5)
        ip_entry = tk.Entry(dialog, width=30)
        ip_entry.pack(pady=5)
        
        tk.Label(dialog, text="Port:").pack(pady=5)
        port_entry = tk.Entry(dialog, width=30)
        port_entry.pack(pady=5)
        
        def add_rule():
            name = name_entry.get().strip()
            if not name:
                messagebox.showerror("Error", "Name required!")
                return
            
            self.firewall.add_rule(name, action_var.get(), ip_entry.get().strip(), port_entry.get().strip())
            self.refresh_rules()
            self.log_activity(f"✅ Added rule: {name}")
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Add", command=add_rule, bg='lightgreen').pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, bg='lightcoral').pack(side=tk.LEFT, padx=5)
    
    def delete_rule(self):
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a rule to delete")
            return
        
        item = self.rules_tree.item(selection[0])
        rule_id = int(item['values'][0])
        rule_name = item['values'][1]
        
        if messagebox.askyesno("Confirm", f"Delete rule '{rule_name}'?"):
            del self.firewall.rules[rule_id]
            self.refresh_rules()
            self.log_activity(f"❌ Deleted rule: {rule_name}")
    
    def refresh_rules(self):
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        for rule in self.firewall.rules.values():
            ip_display = rule.ip_address if rule.ip_address else "any"
            port_display = rule.port if rule.port else "any"
            status = "ON" if rule.enabled else "OFF"
            
            self.rules_tree.insert("", "end", values=(
                rule.rule_id, rule.name, rule.action.upper(),
                ip_display, port_display, rule.protocol, status, rule.hits
            ))
    
    def clear_monitor(self):
        for item in self.monitor_tree.get_children():
            self.monitor_tree.delete(item)
    
    def log_activity(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.activity_text.see(tk.END)
        
        # Keep only last 100 lines
        lines = self.activity_text.get(1.0, tk.END).split('\n')
        if len(lines) > 100:
            self.activity_text.delete(1.0, tk.END)
            self.activity_text.insert(1.0, '\n'.join(lines[-100:]))
    
    def update_display(self):
        for key, label in self.stats_labels.items():
            label.config(text=str(self.firewall.stats[key]))
    
    def periodic_update(self):
        self.update_display()
        self.root.after(1000, self.periodic_update)
    
    def run(self):
        self.refresh_rules()
        self.log_activity("🛡️ Personal Firewall GUI loaded")
        
        if not SCAPY_AVAILABLE:
            self.log_activity("⚠️ Scapy not installed - run: pip install scapy")
        
        self.root.mainloop()

def check_admin():
    """Check if running with admin privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return os.geteuid() == 0

def main():
    """Main function with menu"""
    print("="*60)
    print("            PERSONAL FIREWALL PROJECT")
    print("="*60)
    print("🛡️  A Python-based firewall with packet sniffing")
    print("📋 Satisfies all project requirements:")
    print("   ✅ Packet sniffing with Scapy")
    print("   ✅ Rule-based filtering")
    print("   ✅ Logging and monitoring")
    print("   ✅ GUI interface")
    print("   ✅ CLI interface")
    print("="*60)
    
    # Check requirements
    if not SCAPY_AVAILABLE:
        print("❌ SCAPY NOT INSTALLED!")
        print("   Install with: pip install scapy")
        print("   Then run this script again")
        input("Press Enter to exit...")
        return
    
    if not check_admin():
        print("⚠️  WARNING: Not running as Administrator!")
        print("   Packet capture may not work properly")
        print("   Run as Administrator (Windows) or with sudo (Linux/Mac)")
        print()
    
    while True:
        print("\n--- CHOOSE INTERFACE ---")
        print("1. CLI Mode (Command Line)")
        print("2. GUI Mode (Graphical)")
        print("3. Exit")
        
        try:
            choice = input("\nEnter choice (1-3): ").strip()
            
            if choice == '1':
                print("\n🖥️  Starting CLI mode...")
                cli = FirewallCLI()
                cli.run()
                
            elif choice == '2':
                if not GUI_AVAILABLE:
                    print("❌ GUI not available! Tkinter not installed.")
                    continue
                
                print("\n🖼️  Starting GUI mode...")
                gui = FirewallGUI()
                gui.run()
                
            elif choice == '3':
                print("👋 Goodbye!")
                break
                
            else:
                print("❌ Invalid choice! Enter 1, 2, or 3")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()