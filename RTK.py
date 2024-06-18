import socket
import base64
import time
import tkinter as tk
from tkinter import messagebox, simpledialog
from threading import Thread
from queue import Queue

# NTRIP client settings
ntrip_server = "rtk.dot.state.mn.us"
ntrip_port = 2101
ntrip_username = "username"
ntrip_password = "password"
ntrip_mountpoint = "RTCM3_MOUNT"

# NTRIP caster settings
caster_server = "localhost"
caster_port = 2102
caster_mountpoint = "REPLAY"
caster_username = ""
caster_password = ""

# Create a queue to store the corrections
correction_queue = Queue()

def connect_to_ntrip(server, port, username, password, mountpoint):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((server, port))
        
        # Send NTRIP request
        request = f"GET /{mountpoint} HTTP/1.1\r\n"
        request += f"User-Agent: NTRIP Client\r\n"
        request += f"Authorization: Basic {base64.b64encode((username + ':' + password).encode()).decode()}\r\n"
        request += f"\r\n"
        sock.sendall(request.encode())
        
        # Read NTRIP response
        response = sock.recv(4096).decode()
        if "200 OK" not in response:
            raise Exception("Failed to connect to NTRIP server")
        
        return sock
    except Exception as e:
        raise Exception(f"Error connecting to NTRIP server: {str(e)}")

def receive_corrections(rtcm_sock):
    try:
        while True:
            data = rtcm_sock.recv(4096)
            if not data:
                break
            correction_queue.put(data)
    except Exception as e:
        log_text(f"Error receiving corrections: {str(e)}")

def send_corrections(caster_sock):
    try:
        # Send NTRIP request with authentication
        request = f"SOURCE {caster_mountpoint} /{caster_mountpoint}\r\n"
        request += f"Source-Agent: NTRIP Replay\r\n"
        if caster_username and caster_password:
            auth = base64.b64encode(f"{caster_username}:{caster_password}".encode()).decode()
            request += f"Authorization: Basic {auth}\r\n"
        request += f"\r\n"
        caster_sock.sendall(request.encode())
        
        while True:
            data = correction_queue.get()
            caster_sock.sendall(data)
    except Exception as e:
        log_text(f"Error sending corrections: {str(e)}")

def start_replay():
    global caster_username, caster_password
    
    # Prompt for caster username and password
    caster_username = simpledialog.askstring("NTRIP Caster", "Enter caster username:")
    caster_password = simpledialog.askstring("NTRIP Caster", "Enter caster password:", show="*")
    
    try:
        # Connect to the NTRIP server
        log_text("Connecting to NTRIP server...")
        ntrip_sock = connect_to_ntrip(ntrip_server, ntrip_port, ntrip_username, ntrip_password, ntrip_mountpoint)
        log_text("Connected to NTRIP server")
        
        # Connect to the NTRIP caster
        log_text("Connecting to NTRIP caster...")
        caster_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        caster_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        caster_sock.connect((caster_server, caster_port))
        log_text("Connected to NTRIP caster")
        
        # Start the receive and send threads
        log_text("Starting correction replay...")
        receive_thread = Thread(target=receive_corrections, args=(ntrip_sock,))
        send_thread = Thread(target=send_corrections, args=(caster_sock,))
        receive_thread.start()
        send_thread.start()
        
    except Exception as e:
        log_text(f"Error: {str(e)}")
        messagebox.showerror("Error", str(e))

def stop_replay():
    log_text("Stopping replay...")
    root.quit()

def log_text(text):
    log_textbox.insert(tk.END, text + "\n")
    log_textbox.see(tk.END)

# Create the main window
root = tk.Tk()
root.title("NTRIP Replay")

# Create the start button
start_button = tk.Button(root, text="Start Replay", command=start_replay)
start_button.pack(pady=10)

# Create the stop button
stop_button = tk.Button(root, text="Stop Replay", command=stop_replay)
stop_button.pack()

# Create the log textbox
log_textbox = tk.Text(root, height=10, width=50)
log_textbox.pack(padx=10, pady=10)

# Start the GUI event loop
root.mainloop()
