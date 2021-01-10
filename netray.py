import tkinter as tk
from ipwhois import IPWhois
import re
import pprint as pp
import socket

def scan_domain():
    target_domain = str(ent_domainInput.get())

    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_domain) is not None:
        target = IPWhois(target_domain)
        whoisResults = target.lookup_whois()

    elif re.search(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", target_domain) is not None:
        target = socket.gethostbyname(target_domain)
        target = IPWhois(target)
        whoisResults = target.lookup_whois()

    else:
        whoisResults = str("Not IP or Domain")

    presults = pp.pformat(whoisResults, indent=2)

    lbl_result["text"] = presults

mainWindow = tk.Tk()
mainWindow.title("NetRay")
mainWindow.resizable(width=True, height=True)


frm_basic = tk.Frame(master=mainWindow)

lbl_domainInput = tk.Label(master=frm_basic, text="Domain/IP: ")
ent_domainInput = tk.Entry(master=frm_basic,width=100)
lbl_result = tk.Label(master=mainWindow, text="Scan results")

btn_scanButton = tk.Button(
    master=mainWindow,
    text="Scan WHOIS",
    width = 10,
    height = 2,
    command=scan_domain)

frm_basic.grid(row=0, column=0, padx=10)
lbl_domainInput.grid(row=0, column=0, sticky="e")
ent_domainInput.grid(row=0, column=1, sticky="w")
btn_scanButton.grid(row=0, column=2, pady=10)
lbl_result.grid(row=1, column=0, padx=10, pady=10)

mainWindow.mainloop()