import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from ipwhois import IPWhois
import re
import pprint as pp
import socket
import requests
from shodan import Shodan

mainWindow = tk.Tk()
mainWindow.title("NetRay")
mainWindow.resizable(width=False, height=False)


frm_basic = tk.Frame(master=mainWindow)
frm_buttons = tk.Frame(mainWindow)

lbl_domainInput = tk.Label(master=frm_basic, text="Domain/IP: ")
lbl_passiveTotalApi = tk.Label(master=frm_basic, text="Passive Total api key:")
lbl_passiveTotalEmail = tk.Label(master=frm_basic, text="Passive Total email:")
lbl_shodanApi = tk.Label(master=frm_basic, text="Shodan API key:")
ent_domainInput = tk.Entry(master=frm_basic,width=100)
ent_passiveTotalEmail = tk.Entry(master=frm_basic, width=100)
ent_passiveTotalApi = tk.Entry(master=frm_basic, width=100)
ent_shodanApi = tk.Entry(master=frm_basic, width=100)
lbl_result = ScrolledText(master=mainWindow, width=117)


def scan_whois():
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

    lbl_result.configure(state="normal")
    lbl_result.delete("1.0", tk.END)
    lbl_result.insert("1.0", presults)
    lbl_result.configure(state="disabled")
    lbl_result.bind("<Button>", lambda event: lbl_result.focus_set())

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
    pdns_formated = pp.pformat(pdns_results)

    lbl_result.configure(state="normal")
    lbl_result.delete("1.0", tk.END)
    lbl_result.insert("1.0", pdns_formated)
    lbl_result.configure(state="disabled")
    lbl_result.bind("<Button>", lambda event: lbl_result.focus_set())

def shodan_lookup():
    key = ent_shodanApi.get()
    shodan_api = Shodan(key)    
    target_domain = str(ent_domainInput.get())
    target = socket.gethostbyname(target_domain)

    shodan_info = shodan_api.host(target)
    shodan_results = pp.pformat(shodan_info)

    lbl_result.configure(state="normal")
    lbl_result.delete("1.0", tk.END)
    lbl_result.insert("1.0", shodan_results)
    lbl_result.configure(state="disabled")
    lbl_result.bind("<Button>", lambda event: lbl_result.focus_set())
    

btn_whoisButton = tk.Button(
    frm_buttons,
    text="Scan WHOIS",
    width = 20,
    height = 2,
    command=scan_whois)

btn_shodanButton = tk.Button(
    frm_buttons,
    text = "Shodan lookup",
    width=20,
    height=2,
    command=shodan_lookup)

btn_passiveTotalLookup = tk.Button(
    frm_buttons,
    text= "PT PDNS lookup",
    width=20,
    height=2,
    command=passivetotal_lookup)

frm_basic.grid(row=0, column=0, padx=10)
frm_buttons.grid(row=0, column=3, sticky="ne")
lbl_domainInput.grid(row=0, column=0, sticky="w")
ent_domainInput.grid(row=0, column=1)
lbl_passiveTotalEmail.grid(row=1, column=0,sticky="w")
ent_passiveTotalEmail.grid(row=1, column=1)
lbl_passiveTotalApi.grid(row=2, column=0, sticky="w")
ent_passiveTotalApi.grid(row=2, column=1)
lbl_shodanApi.grid(row=3, column=0, sticky="w")
ent_shodanApi.grid(row=3, column=1)
btn_whoisButton.grid(row=0, column=2)
btn_shodanButton.grid(row=1, column=2)
btn_passiveTotalLookup.grid(row=2, column=2)
lbl_result.grid(row=1, column=0, padx=10, pady=10, sticky="w")

mainWindow.mainloop()
