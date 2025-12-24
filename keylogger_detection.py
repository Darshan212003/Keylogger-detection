import psutil

suspicious_words = ["keylog", "logger", "spy", "hook", "record"]

print("Scanning system processes...\n")

found = False

for process in psutil.process_iter(['pid', 'name']):
    try:
        process_name = process.info['name'].lower()

        for word in suspicious_words:
            if word in process_name:
                print("⚠️ Suspicious Process Detected!")
                print("Process Name:", process.info['name'])
                print("Process ID:", process.info['pid'])
                found = True

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

if not found:
    print("✅ No suspicious keylogger activity detected.")
