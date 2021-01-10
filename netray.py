import tkinter as tk
from ipwhois import IPWhois
import re
import pprint as pp
import socket
import requests

mainWindow = tk.Tk()
mainWindow.title("NetRay")
mainWindow.resizable(width=True, height=True)


frm_basic = tk.Frame(master=mainWindow)
frm_buttons = tk.Frame(mainWindow)

lbl_domainInput = tk.Label(master=frm_basic, text="Domain/IP: ")
lbl_passiveTotalApi = tk.Label(master=frm_basic, text="Passive Total api key:")
lbl_passiveTotalEmail = tk.Label(master=frm_basic, text="Passive Total email:")
ent_domainInput = tk.Entry(master=frm_basic,width=100)
ent_passiveTotalEmail = tk.Entry(master=frm_basic, width=100)
ent_passiveTotalApi = tk.Entry(master=frm_basic, width=100)
lbl_result = tk.Label(master=mainWindow, text="Scan results")

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

def passivetotal_lookup():
    username = ent_passiveTotalEmail.get()
    key = ent_passiveTotalApi.get()
    auth = (username, key)
    base_url = "https://api.passivetotal.org"

    def passivetotal_get(path, query):
        url = base_url + path
        data = {'query': query}

        response = requests.get(url, auth=auth, json=data)
        return response.json()

    pdns_results = passivetotal_get('/v2/dns/passive', str(ent_domainInput.get()))

    pdnsresults_format = pp.pformat(pdns_results)
    lbl_result["text"] = pdnsresults_format

def ping_domain():
    target_domain = str(ent_domainInput.get())
    print(target_domain)

btn_scanButton = tk.Button(
    frm_buttons,
    text="Scan WHOIS",
    width = 20,
    height = 2,
    command=scan_domain)

btn_pingButton = tk.Button(
    frm_buttons,
    text = "Ping host",
    width=20,
    height=2,
    command=ping_domain)

btn_passiveTotalLookup = tk.Button(
    frm_buttons,
    text= "PT PDNS lookup",
    width=20,
    height=2,
    command=passivetotal_lookup
)

frm_basic.grid(row=0, column=0, padx=10)
frm_buttons.grid(row=0, column=3, sticky="ne")
lbl_domainInput.grid(row=0, column=0,)
ent_domainInput.grid(row=0, column=1,)
lbl_passiveTotalEmail.grid(row=1, column=0)
ent_passiveTotalEmail.grid(row=1, column=1)
lbl_passiveTotalApi.grid(row=2, column=0)
ent_passiveTotalApi.grid(row=2, column=1)
btn_scanButton.grid(row=0, column=2)
btn_pingButton.grid(row=1, column=2)
btn_passiveTotalLookup.grid(row=2, column=2)
lbl_result.grid(row=1, column=0, padx=10, pady=10, sticky="w")

mainWindow.mainloop()