import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
import datetime

# Advanced security audit logic with hybrid detection, conflict resolution, and optimization

def analyze_firewall_rules(rules):
    findings = []
    optimizations = []
    rule_set = set()
    conflict_rules = []

    for idx, rule in enumerate(rules):
        action, protocol, source, destination, port = rule
        rule_key = (action.upper(), protocol, source, destination, port)

        # Detect redundancy
        if rule_key in rule_set:
            findings.append(f"🔁 Rule {idx+1}: Duplicate rule detected.")
        else:
            rule_set.add(rule_key)

        # Check for overly permissive rules
        if source == '0.0.0.0/0' and action.upper() == 'ALLOW':
            findings.append(f"⚠️ Rule {idx+1}: Allows ALL incoming traffic from anywhere.")

        if port in ['22', '3389'] and source == '0.0.0.0/0':
            findings.append(f"🚨 Rule {idx+1}: Critical port {port} open to the internet!")

        if destination == '0.0.0.0/0' and action.upper() == 'ALLOW':
            findings.append(f"⚠️ Rule {idx+1}: Allows traffic to any destination.")

        if port == 'ANY' and action.upper() == 'ALLOW':
            findings.append(f"⚠️ Rule {idx+1}: Allows all ports, consider restricting.")

        # Detect basic conflict patterns
        for jdx, other_rule in enumerate(rules):
            if idx != jdx and rule[:4] == other_rule[:4] and rule[4] != other_rule[4]:
                conflict_rules.append((idx+1, jdx+1))

    if conflict_rules:
        for r1, r2 in conflict_rules:
            findings.append(f"❌ Conflict detected between Rule {r1} and Rule {r2}.")

    if not findings:
        optimizations.append("✅ Good job! No major security issues found.")
    else:
        optimizations.append("🔧 Review and tighten overly broad, redundant, or conflicting rules.")

    log_audit(findings)
    return findings, optimizations

def log_audit(entries):
    with open("firewall_audit_log.txt", "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n=== Audit Log Entry @ {timestamp} ===\n")
        for entry in entries:
            f.write(f"{entry}\n")

# GUI Class
class FirewallReviewApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🚡️ Firewall Configuration Review Tool")
        self.root.geometry('1200x800')
        self.root.configure(bg='#e6f2ff')

        self.rules = []

        # Title
        tk.Label(root, text="Firewall Rule Analyzer & Optimizer", font=('Arial', 22, 'bold'), bg='#e6f2ff', fg='#003366').pack(pady=10)

        # Buttons
        btn_frame = tk.Frame(root, bg='#e6f2ff')
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="📁 Load Rules", command=self.load_rules, bg="#3399ff", fg="white", font=('Arial', 12)).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🔍 Analyze", command=self.analyze_rules, bg="#0066cc", fg="white", font=('Arial', 12)).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🛠️ Resolve Suggestions", command=self.resolve_rules, bg="#28a745", fg="white", font=('Arial', 12)).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="📥 Export Rules", command=self.export_rules, bg="#ff9933", fg="white", font=('Arial', 12)).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🔢 Simulate Rule", command=self.simulate_rule_flow, bg="#9933ff", fg="white", font=('Arial', 12)).pack(side=tk.LEFT, padx=5)

        # Treeview for rules
        self.tree = ttk.Treeview(root, columns=('Action', 'Protocol', 'Source', 'Destination', 'Port'), show='headings')
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Text Output
        self.result_text = tk.Text(root, height=12, bg='#f0f8ff', font=('Arial', 12))
        self.result_text.pack(pady=10, fill=tk.BOTH, expand=True)
        self.result_text.tag_configure("heading", font=('Arial', 14, 'bold'))

    def load_rules(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    reader = csv.reader(file)
                    self.rules = list(reader)[1:]  # Skip header
                self.populate_tree()
                messagebox.showinfo("Success", "Firewall rules loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load rules: {e}")

    def export_rules(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            try:
                with open(file_path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Action', 'Protocol', 'Source', 'Destination', 'Port'])
                    for rule in self.rules:
                        writer.writerow(rule)
                messagebox.showinfo("Exported", "Rules exported successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")

    def populate_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for rule in self.rules:
            self.tree.insert('', tk.END, values=rule)

    def analyze_rules(self):
        if not self.rules:
            messagebox.showwarning("Warning", "Please load firewall rules first!")
            return

        findings, optimizations = analyze_firewall_rules(self.rules)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, "🔎 Findings:\n", "heading")
        for finding in findings:
            self.result_text.insert(tk.END, f"{finding}\n")

        self.result_text.insert(tk.END, "\n✅ Suggestions:\n", "heading")
        for opt in optimizations:
            self.result_text.insert(tk.END, f"{opt}\n")

    def resolve_rules(self):
        if not self.rules:
            messagebox.showwarning("Warning", "Load rules before resolving.")
            return

        findings, _ = analyze_firewall_rules(self.rules)
        if not findings:
            messagebox.showinfo("No Issues", "No issues to resolve!")
            return

        resolution_window = tk.Toplevel(self.root)
        resolution_window.title("Resolution Recommendations")
        resolution_window.geometry("700x500")

        label = tk.Label(resolution_window, text="Resolution Options", font=('Arial', 16, 'bold'))
        label.pack(pady=10)

        text_box = tk.Text(resolution_window, wrap='word', font=('Arial', 12))
        text_box.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        for i, finding in enumerate(findings):
            suggestion = f"🔧 Suggestion {i+1}: Consider reviewing: {finding}\n"
            text_box.insert(tk.END, suggestion)

        text_box.config(state='disabled')

    def simulate_rule_flow(self):
        if not self.rules:
            messagebox.showwarning("Warning", "Load rules to simulate.")
            return

        sim_win = tk.Toplevel(self.root)
        sim_win.title("Simulate Packet Flow")
        sim_win.geometry("500x300")

        tk.Label(sim_win, text="Enter simulated packet details", font=('Arial', 12, 'bold')).pack(pady=10)

        frame = tk.Frame(sim_win)
        frame.pack(pady=5)

        labels = ["Protocol", "Source", "Destination", "Port"]
        entries = {}
        for lbl in labels:
            row = tk.Frame(frame)
            row.pack(fill=tk.X, padx=5, pady=5)
            tk.Label(row, text=lbl, width=15).pack(side=tk.LEFT)
            ent = tk.Entry(row)
            ent.pack(side=tk.RIGHT, expand=True, fill=tk.X)
            entries[lbl] = ent

        def run_simulation():
            proto = entries["Protocol"].get()
            src = entries["Source"].get()
            dst = entries["Destination"].get()
            port = entries["Port"].get()
            match_found = False

            for rule in self.rules:
                action, rproto, rsrc, rdst, rport = rule
                if (proto == rproto and src == rsrc and dst == rdst and (port == rport or rport == 'ANY')):
                    messagebox.showinfo("Match Found", f"Matched rule: {rule} => {action}")
                    match_found = True
                    break

            if not match_found:
                messagebox.showinfo("No Match", "No matching rule found. Default action applied.")

        tk.Button(sim_win, text="Run Simulation", command=run_simulation, bg="#0066cc", fg="white", font=('Arial', 12)).pack(pady=10)

# Run App
if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallReviewApp(root)
    root.mainloop()