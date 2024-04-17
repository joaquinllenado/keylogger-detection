import psutil
import keylogPacketSniffer
import time
from tkinter import END

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

    # First scan for names
    results_listbox.delete(0, END)  # Clear previous results
    detected_keyloggers = scan_for_keyloggers()
    if detected_keyloggers:
        for process in detected_keyloggers:
            results_listbox.insert(END, process.name())
    else:
        results_listbox.insert(END, "No suspicious process names found.\r")
    
    # Second scan for packets
    results_listbox.insert(END, "Now scanning packet data...\r")
    # Scan packets
    network_stats = keylogPacketSniffer.scan_network_traffic(duration=10)
    # Print the extracted network traffic statistics
    for (src_ip, src_port, dst_ip, dst_port, protocol), stats in network_stats.items():
        results_listbox.insert( END, f"Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}, Protocol: {protocol}")
        for key, value in stats.items():
            results_listbox.insert(END, f"{key}: {value}\r")
        print()

    # Process packets to be inserted into prediction model
    preprocessed_system_info = keylogPacketSniffer.preprocess_system_info(network_stats)

    # Predict based on packets and display 
    results_listbox.insert(END, keylogPacketSniffer.detection_model.predict(preprocessed_system_info))

def quit_application(window):
    window.destroy()


