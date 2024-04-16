import psutil
from tkinter import Tk, Label, Button, Listbox, Scrollbar, END

def scan_for_keyloggers():
    keylogger_programs = [
        "spyrix", "refog", "ardamax", "kidlogger", "perfect keylogger", "elite keylogger",
        "actual keylogger", "hoverwatch", "refog personal monitor", "wolfeye keylogger",
        "micro keylogger", "revealer keylogger", "all in one keylogger", "blackbox express",
        "ghost keylogger", "keylogger pro", "netbull", "pc tattletale", "remote keylogger",
        "softactivity keylogger", "specter pro", "spytech spyagent", "win-spy software",
        "imonitor keylogger", "free keylogger", "perfect keylogger for mac", "actual spy",
        "real free keylogger", "keyprowler", "spyshelter", "keylogger", "spycam",
    ]

    detected_keyloggers = []
    for process in psutil.process_iter():
        process_name = process.name().lower()
        if any(keyword in process_name for keyword in keylogger_programs):
            detected_keyloggers.append(process)

    return detected_keyloggers


def display_results(results_listbox):
    results_listbox.delete(0, END)  # Clear previous results
    detected_keyloggers = scan_for_keyloggers()
    if detected_keyloggers:
        for process in detected_keyloggers:
            results_listbox.insert(END, process.name())
    else:
        results_listbox.insert(END, "No suspicious processes found.")

def quit_application(window):
    window.destroy()

def main():
    window = Tk()
    window.title("Keylogger Scanner")

    # Title label
    title_label = Label(window, text="Scan for Keyloggers", font=("Arial", 16))
    title_label.pack(pady=20)
    
    # Results listbox
    results_listbox = Listbox(window, width=50)
    results_scrollbar = Scrollbar(window, orient="vertical", command=results_listbox.yview)
    results_listbox.config(yscrollcommand=results_scrollbar.set)
    results_scrollbar.pack(side="right", fill="y")
    results_listbox.pack(pady=10)

    # Scan button
    scan_button = Button(window, text="Scan Now", command=lambda: display_results(results_listbox))
    scan_button.pack(side="top", padx=5)

    # Quit button
    quit_button = Button(window, text="Quit", command=lambda: quit_application(window))
    quit_button.pack(side="top", padx=5)

    window.mainloop()

if __name__ == "__main__":
    main()
