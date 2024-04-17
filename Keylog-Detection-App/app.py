import keylogNameDetection
from tkinter import Tk, Label, Button, Listbox, Scrollbar, END

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
    scan_button = Button(window, text="Scan Now", command=lambda: keylogNameDetection.display_results(results_listbox))
    scan_button.pack(side="top", padx=5)

    # Quit button
    quit_button = Button(window, text="Quit", command=lambda: keylogNameDetection.quit_application(window))
    quit_button.pack(side="top", padx=5)

    window.mainloop()

if __name__ == "__main__":
    main()
