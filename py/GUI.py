import tkinter as tk
import psutil
import scapy.all as sc
import netifaces
import time
import threading
import os
import signal

from PIL import Image, ImageTk
from tkinter import ttk, filedialog, font

from tool import tool_exec

def RedshiftGUI():

    current_directory = os.path.dirname(os.path.abspath(__file__))


    def get_network_interfaces():
        """Ottiene la lista delle interfacce di rete disponibili."""
        return list(psutil.net_if_addrs().keys())

    def get_subnet(interface):
        """Ottiene la subnet dell'interfaccia selezionata."""
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr'] + "/24"
        except Exception as e:
            print(f"Error in getting subnet: {e}")
        return None

    def scan_network():
        """Scansiona la rete per trovare host attivi."""
        hosts = []
        interface = interface_var.get()
        subnet = get_subnet(interface)
        if not subnet:
            status_label.config(text="Error: Impossible to find subnet.")
            return []
            
        # Mostra la progress bar e inizia l'animazione
        progress.tkraise()
        progress.start(10)
        
        print(f"Scanning subnet: {subnet}")
        arp_request = sc.ARP(pdst=subnet)
        broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Simula il tempo di attesa della scansione
        time.sleep(1) 
        
        answered_list = sc.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        for element in answered_list:
            hosts.append((element[1].psrc, element[1].hwsrc))
        
        if not hosts:
            print("No host found. Try launching as root.")
            
        # Ferma e nasconde la progress bar
        progress.stop()
        progress.lower()
        
        return hosts
            
    def update_table():
        """Aggiorna la tabella con gli host trovati."""
        for row in tree.get_children():
            tree.delete(row)
            
        # Avvia la progress bar e forza l'aggiornamento della GUI
        progress.start(10)
        root.update_idletasks()
        
        # Avvia la scansione in un thread separato per non bloccare la GUI
        def scan_and_update():
            hosts = scan_network()
            
            # Aggiorna la tabella nella GUI (deve essere eseguito nel thread principale)
            root.after(0, lambda: fill_table(hosts))
            
            # Ferma la progress bar
            root.after(0, progress.stop)

        threading.Thread(target=scan_and_update, daemon=True).start()    

    def fill_table(hosts):
        """Riempie la tabella con gli host trovati."""
        for host in hosts:
            tree.insert("", tk.END, values=host)

    def add_to_host1():
        selected = tree.selection()
        if selected:
            host1_var.set(tree.item(selected[0], 'values')[0])

    def add_to_host2():
        selected = tree.selection()
        if selected:
            host2_var.set(tree.item(selected[0], 'values')[0])
            
    def load_rule_file():
        file_path = filedialog.askopenfilename(title="Select Rule File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            rule_file_var.set(file_path)
            rule_check_label.config(image=check_photo)

    def update_rule_state():
        """Aggiorna lo stato della regola e rimuove la spunta se torna a Default."""
        if rule_option.get() == "default":
            rule_check_label.config(image="")
            rule_file_var.set("")

    def load_payload_file():
        file_path = filedialog.askopenfilename(title="Select Payload File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            payload_file_var.set(file_path)
            payload_check_label.config(image=check_photo)
        
    def update_payload_state():
        """Aggiorna lo stato del payload e rimuove la spunta se torna a Default."""
        if payload_option.get() == "default":
            payload_check_label.config(image="")
            payload_file_var.set("")

    def launch_script():
        """Esegue lo script .sh con i parametri inseriti."""
        ip1 = host1_var.get()
        ip2 = host2_var.get()
        interface = interface_var.get()

        config_directory = os.path.join(current_directory, '..', 'config')
        config_directory = os.path.normpath(config_directory)
        
        # Controllo regole
        if rule_option.get() == "custom" and rule_file_var.get():
            rule_file = rule_file_var.get()
        else:
            rule_file = f"{config_directory}/rule.txt"
        
        # Controllo payload
        if payload_option.get() == "custom" and payload_file_var.get():
            payload_file = payload_file_var.get()
        else:
            payload_file = f"{config_directory}/payload.txt"
        
        # Controllo host
        if ip1 and ip2 and interface:
            tool_exec(ip1, ip2, interface, rule_file, payload_file)
            
            # Messaggio di stato con il nome dei file effettivamente usati
            status_message = f"Executed with {ip1}, {ip2}, {interface}, "
            status_message += f"Regola: {rule_file}, Payload: {payload_file}"
            status_label.config(text=status_message)
            
        else:
            status_label.config(text="Error: no hosts selected!")
            
    def stop_script():
        try:
            print(f"Stopping...")
            os.kill(os.getpid(), signal.SIGINT)
        except Exception as e:
            pass

    # favicon
    icon_path = f"{current_directory}/../images/favicon.png"

    # Creazione finestra
    root = tk.Tk()
    root.iconphoto(False, tk.PhotoImage(file=icon_path))
    root.title("RedShift")
    root.geometry("600x500")
    root.configure(bg="black")

    # Variabili per le opzioni
    rule_option = tk.StringVar(value="default")
    payload_option = tk.StringVar(value="default")
    rule_file_var = tk.StringVar()
    payload_file_var = tk.StringVar()

    # Caricamento immagini (placeholder)
    background_img = Image.open(f"{current_directory}/../images/background.png")
    background_img = background_img.resize((800, 500), Image.LANCZOS)
    background_photo = ImageTk.PhotoImage(background_img)

    title_img = Image.open(f"{current_directory}/../images/title.png")
    title_img = title_img.resize((310, 80), Image.LANCZOS)
    title_photo = ImageTk.PhotoImage(title_img)

    # Background
    canvas = tk.Canvas(root, width=800, height=500, bg="black", highlightthickness=0)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=background_photo, anchor="nw")

    # Titolo
    title_label = tk.Label(root, image=title_photo, bg="black")
    title_label.place(x=150, y=0)

    # Menu a tendina per interfacce di rete
    interface_var = tk.StringVar()
    interfaces = get_network_interfaces()
    interface_dropdown = ttk.Combobox(root, textvariable=interface_var, values=interfaces, state="readonly")
    interface_dropdown.place(x=155, y=90)
    if interfaces:
        interface_var.set(interfaces[0])
        
    scan_font = font.Font(size=9)
        
    # Pulsante "scansiona rete"
    tk.Button(root, text="Scan network", command=update_table, bg="gray", width=10, height=1, font=scan_font).place(x=342, y=87)

    style = ttk.Style()
    style.theme_use("classic")
    style.configure("Horizontal.TProgressbar", thickness=1, background="red")  # Cambia l'altezza

    # Creazione della progress bar
    progress = ttk.Progressbar(root, length=108, mode="indeterminate", style="Horizontal.TProgressbar")
    progress.place(x=342, y=116)
    progress.lower()

    # Tabella con IP e MAC
    tree = ttk.Treeview(root, columns=("IP Address", "MAC Address"), show="headings")
    tree.heading("IP Address", text="IP Address")
    tree.heading("MAC Address", text="MAC Address")
    tree.place(x=100, y=130, width=400, height=150)

    # Variabili per gli host selezionati
    host1_var = tk.StringVar()
    host2_var = tk.StringVar()

    entry_font = font.Font(size=9)
    host_font = font.Font(size=11)
    debug_font = font.Font(size=8)

    # Pulsanti per selezionare gli host con dimensioni personalizzate
    tk.Button(root, text="Add to Host 1", command=add_to_host1, bg="gray", width=10, height=1, font=entry_font).place(x=9, y=300)
    tk.Entry(root, textvariable=host1_var, state="readonly", width=18, font=host_font).place(x=127, y=302)

    tk.Button(root, text="Add to Host 2", command=add_to_host2, bg="gray", width=10, height=1, font=entry_font).place(x=306, y=300)
    tk.Entry(root, textvariable=host2_var, state="readonly", width=18, font=host_font).place(x=424, y=302)

    style = ttk.Style()
    style.theme_use("classic")

    ## Opzioni per Rule
    rule_label = tk.Label(root, text="Rule File:", fg="white", bg="black")
    rule_label.place(x=30, y=350)

    tk.Radiobutton(root, text="Default", variable=rule_option, value="default", bg="gray", command=lambda: [rule_button.config(state=tk.DISABLED), update_rule_state()], width=10, indicatoron=1).place(x=150, y=350)

    tk.Radiobutton(root, text="Custom", variable=rule_option, value="custom", bg="gray", command=lambda: rule_button.config(state=tk.NORMAL), width=10).place(x=260, y=350)
    rule_button = tk.Button(root, text="Load File", command=load_rule_file, state=tk.DISABLED)

    rule_button.place(x=400, y=345)

    # Opzioni per Payload
    payload_label = tk.Label(root, text="Payload File:", fg="white", bg="black")
    payload_label.place(x=30, y=400)

    tk.Radiobutton(root, text="Default", variable=payload_option, value="default", bg="gray", command=lambda: [rule_button.config(state=tk.DISABLED), update_payload_state()], width=10).place(x=150, y=400)

    tk.Radiobutton(root, text="Custom", variable=payload_option, value="custom", bg="gray", command=lambda: payload_button.config(state=tk.NORMAL), width=10).place(x=260, y=400)

    payload_button = tk.Button(root, text="Load File", command=load_payload_file, state=tk.DISABLED)
    payload_button.place(x=400, y=395)

    # Caricamento icona di spunta
    check_img = Image.open(f"{current_directory}/../images/check.png") 
    check_img = check_img.resize((20, 20), Image.LANCZOS)
    check_photo = ImageTk.PhotoImage(check_img)

    # Etichette per la spunta
    rule_check_label = tk.Label(root, bg="black")
    rule_check_label.place(x=540, y=350)

    payload_check_label = tk.Label(root, bg="black")
    payload_check_label.place(x=540, y=400)

    # Pulsante per avviare lo script
    launch_button = tk.Button(root, text="Run", command=launch_script, bg="red", fg="white", width=10)
    launch_button.place(x=200, y=440)
    
    # Pulsante per fermare lo script (si spera)
    stop_button = tk.Button(root, text="Stop", command=stop_script, bg="white", fg="red", width=10)
    stop_button.place(x=320, y=440)

    # Etichetta per stato
    status_label = tk.Label(root, text="", fg="white", bg="black", font=debug_font)
    status_label.place(x=0, y=480)
    root.resizable(False, False)

    root.mainloop()
