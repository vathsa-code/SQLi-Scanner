import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from main import scan_sql_injection
import threading

# --- Scan Trigger ---
def run_scan():
    url = url_entry.get().strip()
    mode = mode_var.get()

    if not url:
        messagebox.showerror("Error", "Please enter a target URL.")
        return

    log_area.delete("1.0", tk.END)
    verdict_var.set("Scanning...")

    def task():
        try:
            scan_sql_injection(url, mode, log_area, verdict_var)
            log_area.insert(tk.END, "\n✅ Scan complete.\n")
        except Exception as e:
            log_area.insert(tk.END, f"\n❌ Error: {e}\n")
            verdict_var.set("❌ Error during scan")

    threading.Thread(target=task).start()

# --- GUI Window ---
root = tk.Tk()
root.title("SQL Injection Scanner")
root.geometry("1000x600")
root.resizable(True, True)

# --- Main 2-Column Layout ---
main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)

main_frame.columnconfigure(0, weight=0, minsize=300)
main_frame.columnconfigure(1, weight=1)

# --- Left Side Frame ---
left_frame = ttk.Frame(main_frame, padding=10)
left_frame.grid(row=0, column=0, sticky="ns")

# --- Right Side Frame (Log) ---
right_frame = ttk.Frame(main_frame, padding=10)
right_frame.grid(row=0, column=1, sticky="nsew")
right_frame.rowconfigure(0, weight=1)
right_frame.columnconfigure(0, weight=1)

# --- Left Column Widgets ---
ttk.Label(left_frame, text="🔗 Target URL:").pack(anchor="w", pady=(0, 5))
url_entry = ttk.Entry(left_frame, width=40)
url_entry.pack(pady=(0, 15))

ttk.Label(left_frame, text="🧪 Payload Mode:").pack(anchor="w")
mode_var = tk.StringVar(value="basic")
mode_menu = ttk.Combobox(left_frame, textvariable=mode_var, values=["basic", "advanced"], state="readonly", width=20)
mode_menu.pack(pady=(0, 15))

ttk.Button(left_frame, text="🚀 Start Scan", command=run_scan).pack(pady=(0, 25))

# --- Verdict Label ---
ttk.Label(left_frame, text="🧾 Verdict:").pack(anchor="w")
verdict_var = tk.StringVar(value="Not started")
verdict_label = ttk.Label(left_frame, textvariable=verdict_var, foreground="blue", font=("Segoe UI", 10, "bold"))
verdict_label.pack(pady=(5, 10))

# --- Right Column: Log Area ---
ttk.Label(right_frame, text="📜 Scan Output:").grid(row=0, column=0, sticky="w")
log_area = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, font=("Courier", 10))
log_area.grid(row=1, column=0, sticky="nsew", pady=(5, 0))

# --- Run the app ---
root.mainloop()
