import tkinter as tk
from ipwhois import IPWhois
import re
import pprint as pp
import socket
import requests
import os
import json
from shodan import Shodan
from censys.search import CensysCerts

mainWindow = tk.Tk()
mainWindow.title("NetRay")
mainWindow.resizable(width=False, height=False)


frm_basic = tk.Frame(master=mainWindow)
frm_buttons = tk.Frame(mainWindow)

lbl_domainInput = tk.Label(master=frm_basic, text="Domain/IP/Certificate (SHA256): ")
lbl_passiveTotalApi = tk.Label(master=frm_basic, text="Passive Total api key:")
lbl_passiveTotalEmail = tk.Label(master=frm_basic, text="Passive Total email:")
lbl_shodanApi = tk.Label(master=frm_basic, text="Shodan API key:")
lbl_censysAPIID = tk.Label(master=frm_basic, text="Censys API ID:")
lbl_censysAPIS = tk.Label(master=frm_basic, text="Censys API Secret:")
ent_domainInput = tk.Entry(master=frm_basic,width=100)
ent_passiveTotalEmail = tk.Entry(master=frm_basic, width=100)
ent_passiveTotalApi = tk.Entry(master=frm_basic, width=100)
ent_shodanApi = tk.Entry(master=frm_basic, width=100)
ent_censysAPIID = tk.Entry(master=frm_basic, width=100)
ent_censysAPIS = tk.Entry(master=frm_basic, width=100)
textContainer = tk.Frame(mainWindow, borderwidth=1, relief="sunken")
dsp_result = tk.Text(textContainer, width=120, height=25, wrap="none", borderwidth=0)
textVsb = tk.Scrollbar(textContainer, orient="vertical", command=dsp_result.yview)
textHsb = tk.Scrollbar(textContainer, orient="horizontal", command=dsp_result.xview)
dsp_result.configure(yscrollcommand=textVsb.set, xscrollcommand=textHsb.set)

# Second result display window
textContainer2 = tk.Frame(mainWindow, borderwidth=1, relief="sunken")
dsp_result2 = tk.Text(textContainer2, width=120, height=25, wrap="none", borderwidth=0)
textVsb2 = tk.Scrollbar(textContainer2, orient="vertical", command=dsp_result2.yview)
textHsb2 = tk.Scrollbar(textContainer2, orient="horizontal", command=dsp_result2.xview)
dsp_result2.configure(yscrollcommand=textVsb2.set, xscrollcommand=textHsb2.set)

window_var = tk.IntVar()
window_var.set(1)

window_select_label = tk.Label(master=frm_buttons, text="Select Result Window")
window_select_label.pack(side="left", padx=5, )

window_one_rb = tk.Radiobutton(master=frm_buttons, text="Window 1", variable=window_var, value=1)
window_one_rb.pack(side="left", padx=5, )

window_two_rb = tk.Radiobutton(master=frm_buttons, text="Window 2", variable=window_var, value=2)
window_two_rb.pack(side="left", padx=5, )

def print_result(window, results):
    window.configure(state="normal")
    window.delete("1.0", tk.END)
    window.insert("1.0", results)
    window.configure(state="disabled")
    window.bind("<Button>", lambda event: window.focus_set())

def scan_whois(window=0):

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

    if window_var.get() == 1:
        print_result(dsp_result, presults)
    elif window_var.get() == 2:
        print_result(dsp_result2, presults)


def passivetotal_lookup(window=0):

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

    if window_var.get() == 1:
        print_result(dsp_result, pdns_formated)
    elif window_var.get() == 2:
        print_result(dsp_result2, pdns_formated)


def shodan_lookup(window=0):

    key = ent_shodanApi.get()
    shodan_api = Shodan(key)    
    target_domain = str(ent_domainInput.get())
    target = socket.gethostbyname(target_domain)

    shodan_info = shodan_api.host(target)
    shodan_results = pp.pformat(shodan_info)

    if window_var.get() == 1:
        print_result(dsp_result, shodan_results)
    elif window_var.get() == 2:
        print_result(dsp_result2, shodan_results)


def censys_cert_lookup(window=0):

    apiid = str(ent_censysAPIID.get())
    apis = str(ent_censysAPIS.get())
    cert = str(ent_domainInput.get())

    os.environ["CENSYS_API_ID"] = apiid
    os.environ["CENSYS_API_SECRET"] = apis
    cen = CensysCerts()
    
    censys_results = cen.view(cert)
    results_p = json.dumps(censys_results, indent=2)

    if window_var.get() == 1:
        print_result(dsp_result, results_p)
    elif window_var.get() == 2:
        print_result(dsp_result2, results_p)

    

def censys_cert_search(window=0):

    apiid = str(ent_censysAPIID.get())
    apis = str(ent_censysAPIS.get())
    cert = str(ent_domainInput.get())

    os.environ["CENSYS_API_ID"] = apiid
    os.environ["CENSYS_API_SECRET"] = apis
    cen = CensysCerts()
    
    query = cen.search(
    cert,
    sort=["parsed.issuer.organization", "parsed.subject.postal_code"],
    pages=2
    )

    cen_hits = query()
    results_p = json.dumps(cen_hits, indent=2)

    if window_var.get() == 1:
        print_result(dsp_result, results_p)
    elif window_var.get() == 2:
        print_result(dsp_result2, results_p)

def on_click(event):
    tag = dsp_result.tag_names(tk.CURRENT)[1]  # get the tag of clicked word
    ent_domainInput.delete(0, tk.END)
    ent_domainInput.insert(0, tag)

btn_whoisScan = tk.Button(master=frm_buttons, text="Whois Scan", command=scan_whois)
btn_passivetotalScan = tk.Button(master=frm_buttons, text="PassiveTotal Lookup", command=passivetotal_lookup)
btn_shodanScan = tk.Button(master=frm_buttons, text="Shodan Scan", command=shodan_lookup)
btn_censysScan = tk.Button(master=frm_buttons, text="Censys Certificate Lookup", command=censys_cert_lookup)
btn_censysSearch = tk.Button(master=frm_buttons, text="Censys Certificate Search", command=censys_cert_search)


# Labels and Entry fields
lbl_domainInput.grid(row=0, column=0, sticky='w', padx=5)
ent_domainInput.grid(row=0, column=1, padx=5)
lbl_passiveTotalApi.grid(row=1, column=0, sticky='w', padx=5)
ent_passiveTotalApi.grid(row=1, column=1, padx=5)
lbl_passiveTotalEmail.grid(row=2, column=0, sticky='w', padx=5)
ent_passiveTotalEmail.grid(row=2, column=1, padx=5)
lbl_shodanApi.grid(row=3, column=0, sticky='w', padx=5)
ent_shodanApi.grid(row=3, column=1, padx=5)
lbl_censysAPIID.grid(row=4, column=0, sticky='w', padx=5)
ent_censysAPIID.grid(row=4, column=1, padx=5)
lbl_censysAPIS.grid(row=5, column=0, sticky='w', padx=5)
ent_censysAPIS.grid(row=5, column=1, padx=5)

frm_basic.pack(padx=10, pady=10)

# Buttons
btn_whoisScan.pack(side="left", padx=5)
btn_passivetotalScan.pack(side="left", padx=5)
btn_shodanScan.pack(side="left", padx=5)
btn_censysScan.pack(side="left", padx=5)
btn_censysSearch.pack(side="left", padx=5)

frm_buttons.pack(padx=10, pady=10)

master_dsp_frame = tk.Frame(mainWindow)
master_dsp_frame.pack()

# Labels and Entry fields
lbl_domainInput.grid(row=0, column=0, sticky='w', padx=5)
ent_domainInput.grid(row=0, column=1, padx=5)
lbl_passiveTotalApi.grid(row=1, column=0, sticky='w', padx=5)
ent_passiveTotalApi.grid(row=1, column=1, padx=5)
lbl_passiveTotalEmail.grid(row=2, column=0, sticky='w', padx=5)
ent_passiveTotalEmail.grid(row=2, column=1, padx=5)
lbl_shodanApi.grid(row=3, column=0, sticky='w', padx=5)
ent_shodanApi.grid(row=3, column=1, padx=5)
lbl_censysAPIID.grid(row=4, column=0, sticky='w', padx=5)
ent_censysAPIID.grid(row=4, column=1, padx=5)
lbl_censysAPIS.grid(row=5, column=0, sticky='w', padx=5)
ent_censysAPIS.grid(row=5, column=1, padx=5)

frm_basic.pack(padx=10, pady=10)

# Buttons
btn_whoisScan.pack(side="left", padx=5)
btn_passivetotalScan.pack(side="left", padx=5)
btn_shodanScan.pack(side="left", padx=5)
btn_censysScan.pack(side="left", padx=5)
btn_censysSearch.pack(side="left", padx=5)

frm_buttons.pack(padx=10, pady=10)

master_dsp_frame = tk.Frame(mainWindow)
master_dsp_frame.pack()

# Text display result 1
textContainer1 = tk.Frame(master=master_dsp_frame)
dsp_result = tk.Text(textContainer1, width=70, height=40, wrap="none", borderwidth=0)
textVsb1 = tk.Scrollbar(textContainer1, orient="vertical", command=dsp_result.yview)
textHsb1 = tk.Scrollbar(textContainer1, orient="horizontal", command=dsp_result.xview)
dsp_result.configure(yscrollcommand=textVsb1.set, xscrollcommand=textHsb1.set)
textVsb1.pack(side="right", fill="y")
textHsb1.pack(side="bottom", fill="x")
dsp_result.pack(side="left", fill="both", expand=True)
textContainer1.grid(row=0, column=0, sticky='nsew')

# Text display result 2
textContainer2 = tk.Frame(master=master_dsp_frame)
dsp_result2 = tk.Text(textContainer2, width=70, height=40, wrap="none", borderwidth=0)
textVsb2 = tk.Scrollbar(textContainer2, orient="vertical", command=dsp_result2.yview)
textHsb2 = tk.Scrollbar(textContainer2, orient="horizontal", command=dsp_result2.xview)
dsp_result2.configure(yscrollcommand=textVsb2.set, xscrollcommand=textHsb2.set)
textVsb2.pack(side="right", fill="y")
textHsb2.pack(side="bottom", fill="x")
dsp_result2.pack(side="left", fill="both", expand=True)
textContainer2.grid(row=0, column=1, sticky='nsew')

dsp_result.tag_configure('highlight', foreground='blue', underline=True)
dsp_result.tag_bind('highlight', '<Button-1>', on_click) # bind left mouse click event to on_click callback
master_dsp_frame.grid_columnconfigure(0, weight=1)
master_dsp_frame.grid_columnconfigure(1, weight=1)

mainWindow.mainloop()