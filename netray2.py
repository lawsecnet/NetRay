import tkinter as tk
from ipwhois import IPWhois
import whois
import re
import pprint as pp
import socket
import requests
import os
import json
from shodan import Shodan
from censys.search import CensysCerts
from censys.search import CensysHosts

mainWindow = tk.Tk()
mainWindow.title("NetRay")
mainWindow.resizable(width=False, height=False)

frm_basic = tk.Frame(master=mainWindow)
frm_buttons = tk.Frame(mainWindow)

lbl_domainInput = tk.Label(master=frm_basic, text="Domain/IP/Certificate (SHA256): ")
lbl_passiveTotalApi = tk.Label(master=frm_basic, text="Passive Total API Key:")
lbl_passiveTotalEmail = tk.Label(master=frm_basic, text="Passive Total Email:")
lbl_shodanApi = tk.Label(master=frm_basic, text="Shodan API key:")
lbl_censysAPIID = tk.Label(master=frm_basic, text="Censys API ID:")
lbl_censysAPIS = tk.Label(master=frm_basic, text="Censys API Secret:")

ent_domainInput = tk.Entry(master=frm_basic,width=100)
ent_passiveTotalEmail = tk.Entry(master=frm_basic, width=100)
ent_passiveTotalApi = tk.Entry(master=frm_basic, width=100)
ent_shodanApi = tk.Entry(master=frm_basic, width=100)
ent_censysAPIID = tk.Entry(master=frm_basic, width=100)
ent_censysAPIS = tk.Entry(master=frm_basic, width=100)

textContainer1 = tk.Frame(mainWindow, borderwidth=0, relief="sunken")
dsp_result1 = tk.Text(textContainer1, width=140, height=25, wrap="none", borderwidth=0)
textVsb1 = tk.Scrollbar(textContainer1, orient="vertical", command=dsp_result1.yview)
textHsb1 = tk.Scrollbar(textContainer1, orient="horizontal", command=dsp_result1.xview)
dsp_result1.configure(yscrollcommand=textVsb1.set, xscrollcommand=textHsb1.set)

textContainer2 = tk.Frame(mainWindow, borderwidth=0, relief="sunken")
dsp_result2 = tk.Text(textContainer2, width=140, height=25, wrap="none", borderwidth=0)
textVsb2 = tk.Scrollbar(textContainer2, orient="vertical", command=dsp_result2.yview)
textHsb2 = tk.Scrollbar(textContainer2, orient="horizontal", command=dsp_result2.xview)
dsp_result2.configure(yscrollcommand=textVsb2.set, xscrollcommand=textHsb2.set)
switch = tk.IntVar()
switch_button = tk.Checkbutton(master=frm_buttons, text="Check for left display", variable=switch)
label1 = tk.Label(textContainer1, text="Display 1")
label2 = tk.Label(textContainer2, text="Display 2")
dsp_switch = False

recordContainer = tk.Frame(master=frm_basic)
dsp_records = tk.Text(recordContainer, width=35, height=12, borderwidth=2, state='disabled')
recordVsb = tk.Scrollbar(recordContainer, orient="vertical", command=dsp_records.yview)
dsp_records.configure(yscrollcommand=recordVsb.set)
dsp_records.grid(row=0, column=0)
recordVsb.grid(row=0, column=1, sticky='ns')


def print_results(presults):
    global dsp_switch
    dsp_result = dsp_result1 if dsp_switch else dsp_result2

    dsp_result.configure(state="normal")
    dsp_result.delete("1.0", tk.END)
    for line in presults.split("\n"):
        # IP addresses (IPv4), domain names, ASNs, email addresses, and JARM hashes
        ip_match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
        domain_match = re.findall(r"\b(?:[a-z]+\.)+[a-z]+\b", line)
        asn_match = re.findall(r"(?:AS)\d+", line)
        asn_json_match = re.findall(r"'asn':\s'\d{3,6}'", line)
        email_match = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", line)
        jarm_match = re.findall(r"\b[a-fA-F\d]{62}\b", line)

        if ip_match or domain_match or asn_match or email_match or jarm_match or asn_json_match:
            # Use insert method with INSERT constant and "tag_name" to place the text in the Text widget with the tag
            for match in ip_match + domain_match + asn_match + email_match + jarm_match:
                dsp_result.insert(tk.INSERT, '\t')
                dsp_result.insert(tk.INSERT, match, ('highlight', match))
                dsp_result.insert(tk.INSERT, '\n')  # new line
        else:
            dsp_result.insert(tk.END, line + '\n')

    dsp_result.configure(state="disabled")

    # switch the display for the next function call
    dsp_switch = not dsp_switch

def add_clickable_results(results, dsp_result):
    dsp_result.configure(state="normal")
    dsp_result.delete("1.0", tk.END)
    for line in results.split("\n"):
        # IP addresses (IPv4), domain names, ASNs, email addresses, JARM hashes and SHA256 hashes
        ip_match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
        domain_match = re.findall(r"\b(?:[a-z]+\.)+[a-z]+\b", line)
        asn_match = re.findall(r"(?:AS)\d+", line)
        asn_json_match = re.findall(r"'asn':\s'\d{3,6}'", line)
        email_match = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", line)
        jarm_match = re.findall(r"\b[a-fA-F\d]{62}\b", line)
        sha256_match = re.findall(r"\b[a-fA-F\d]{64}\b", line)

        if ip_match or domain_match or asn_match or email_match or jarm_match or sha256_match or asn_json_match:
            # Use insert method with INSERT constant and "tag_name" to place the text in the Text widget with the tag
            for match in ip_match + domain_match + asn_match + email_match + jarm_match + sha256_match:
                dsp_result.insert(tk.INSERT, '\t')
                dsp_result.insert(tk.INSERT, match, ('highlight', match))
                dsp_result.insert(tk.INSERT, '\n')  # new line
        else:
            dsp_result.insert(tk.END, line + '\n')  # if no match just insert the line

    dsp_result.configure(state="disabled")


def scan_whois():
    try:
        target_domain = str(ent_domainInput.get())
        if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_domain) is not None:
            target = IPWhois(target_domain)
            whoisResults = target.lookup_whois()
        elif re.search(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", target_domain) is not None:
            whoisResults = whois.whois(target_domain)
        else:
            whoisResults = str("Not IP or Domain")
        presults = pp.pformat(whoisResults, indent=2)
        add_clickable_results(presults, dsp_result1 if switch.get() else dsp_result2)
        update_records(ent_domainInput.get())
    except socket.gaierror as e:
        add_clickable_results(str(e), dsp_result1 if switch.get() else dsp_result2)


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

    add_clickable_results(pdns_formated, dsp_result1 if switch.get() else dsp_result2)
    update_records(ent_domainInput.get())

def shodan_lookup():
    try:
        key = ent_shodanApi.get()
        shodan_api = Shodan(key)    
        target_domain = str(ent_domainInput.get())
        target = socket.gethostbyname(target_domain)

        shodan_info = shodan_api.host(target)
        shodan_results = pp.pformat(shodan_info)

        add_clickable_results(shodan_results, dsp_result1 if switch.get() else dsp_result2)
        update_records(ent_domainInput.get())
    except Exception as e:
        add_clickable_results(str(e), dsp_result1 if switch.get() else dsp_result2)

def shodan_search():
    try:
        key = ent_shodanApi.get()
        shodan_api = Shodan(key)    
        target = str(ent_domainInput.get())

        shodan_info = shodan_api.search(target)
        shodan_results = pp.pformat(shodan_info)

        add_clickable_results(shodan_results, dsp_result1 if switch.get() else dsp_result2)
        update_records(ent_domainInput.get())
    except Shodan.APIError as e:
        add_clickable_results(e, dsp_result1 if switch.get() else dsp_result2)


def censys_cert_lookup():
    try:
        apiid = str(ent_censysAPIID.get())
        apis = str(ent_censysAPIS.get())
        cert = str(ent_domainInput.get())

        os.environ["CENSYS_API_ID"] = apiid
        os.environ["CENSYS_API_SECRET"] = apis
        cen = CensysCerts()
    
        censys_results = cen.view(cert)
        results_p = json.dumps(censys_results, indent=2)

        add_clickable_results(results_p, dsp_result1 if switch.get() else dsp_result2)
        update_records(ent_domainInput.get())
    except Exception as e:
        add_clickable_results(str(e), dsp_result1 if switch.get() else dsp_result2)
    

def censys_cert_search():
    try:
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

        add_clickable_results(results_p, dsp_result1 if switch.get() else dsp_result2)
        update_records(ent_domainInput.get())
    except Exception as e:
        add_clickable_results(str(e), dsp_result1 if switch.get() else dsp_result2)

def censys_host_view():
    try:
        apiid = str(ent_censysAPIID.get())
        apis = str(ent_censysAPIS.get())
        cert = str(ent_domainInput.get())

        os.environ["CENSYS_API_ID"] = apiid
        os.environ["CENSYS_API_SECRET"] = apis
        cen = CensysHosts()
    
        host = cen.view(ent_domainInput.get())
        host_r = json.dumps(host, indent=2)

        add_clickable_results(host_r, dsp_result1 if switch.get() else dsp_result2)
        update_records(ent_domainInput.get())
    except Exception as e:
        add_clickable_results(str(e), dsp_result1 if switch.get() else dsp_result2)


def on_click(event):
    # get the tag of clicked word
    tag = event.widget.tag_names(tk.CURRENT)[1]
    ent_domainInput.delete(0, tk.END)
    ent_domainInput.insert(0, tag)

def update_records(entry):
    dsp_records.configure(state='normal') 
    dsp_records.insert(tk.END, entry + '\n')  
    dsp_records.configure(state='disabled')

def clear_click():
    dsp_records.configure(state='normal')  
    dsp_records.delete('1.0', tk.END)  
    dsp_records.configure(state='disabled')

def btn_whois_click():
    scan_whois()

def btn_pdns_click():
    passivetotal_lookup()

def btn_shodan_click():
    shodan_lookup()

def btn_shodan_search_click():
    shodan_search()

def btn_censys_cert_lookup_click():
    censys_cert_lookup()

def btn_censys_cert_search_click():
    censys_cert_search()

def btn_censys_host_view_click():
    censys_host_view()


# Buttons
btn_whois = tk.Button(master=frm_buttons, text="WHOIS Lookup", command=btn_whois_click, sticky="w")
btn_pdns = tk.Button(master=frm_buttons, text="Passive Total PDNS", command=btn_pdns_click, sticky="w")
btn_shodan = tk.Button(master=frm_buttons, text="Shodan Host Lookup", command=btn_shodan_click, sticky="w")
btn_shodan_search = tk.Button(master=frm_buttons, text="Shodan Search", command=btn_shodan_search_click, sticky="w")
btn_censys_cert_lookup = tk.Button(master=frm_buttons, text="Censys Cert Lookup", command=btn_censys_cert_lookup_click, sticky="w")
btn_censys_cert_search = tk.Button(master=frm_buttons, text="Censys Cert Search", command=btn_censys_cert_search_click, sticky="w")
btn_censys_host_view = tk.Button(master=frm_buttons, text="Censys Host View", command=btn_censys_host_view_click, sticky="w")
btn_clear = tk.Button(master=frm_buttons, text='Clear Records', command=clear_click, sticky="w")

# Layout
lbl_domainInput.grid(row=0, column=0)
lbl_passiveTotalApi.grid(row=1, column=0, sticky='w')
lbl_passiveTotalEmail.grid(row=2, column=0, sticky='w')
lbl_shodanApi.grid(row=3, column=0, sticky='w')
lbl_censysAPIID.grid(row=4, column=0, sticky='w')
lbl_censysAPIS.grid(row=5, column=0, sticky='w')
ent_domainInput.grid(row=0, column=1, sticky='w')
ent_passiveTotalApi.grid(row=1, column=1, sticky='w')
ent_passiveTotalEmail.grid(row=2, column=1, sticky='w')
ent_shodanApi.grid(row=3, column=1, sticky='w')
ent_censysAPIID.grid(row=4, column=1, sticky='w')
ent_censysAPIS.grid(row=5, column=1, sticky='w')

btn_whois.grid(row=0, column=0, padx=2)
btn_pdns.grid(row=0, column=1, padx=2)
btn_shodan.grid(row=0, column=2, padx=2)
btn_shodan_search.grid(row=1, column=2, padx=2)
btn_censys_cert_lookup.grid(row=0, column=3, padx=2)
btn_censys_cert_search.grid(row=1, column=3, padx=2)
btn_censys_host_view.grid(row=2, column=3, padx=2)
btn_clear.grid(row=0, column=4, padx=2)
switch_button.grid(row=0, column=5, padx=2)

textContainer1 = tk.Frame(mainWindow)
dsp_result1 = tk.Text(textContainer1, width=70, height=50, wrap="none", borderwidth=0)
textVsb1 = tk.Scrollbar(textContainer1, orient="vertical", command=dsp_result1.yview)
textHsb1 = tk.Scrollbar(textContainer1, orient="horizontal", command=dsp_result1.xview)
dsp_result1.configure(yscrollcommand=textVsb1.set, xscrollcommand=textHsb1.set)
dsp_result1.grid(row=0, column=0, sticky='nsew')
textVsb1.grid(row=0, column=1, sticky='ns')
textHsb1.grid(row=1, column=0, sticky='ew')
textContainer1.grid_columnconfigure(0, weight=1)
textContainer1.grid_rowconfigure(0, weight=1)

textContainer2 = tk.Frame(mainWindow)
dsp_result2 = tk.Text(textContainer2, width=70, height=50, wrap="none", borderwidth=0)
textVsb2 = tk.Scrollbar(textContainer2, orient="vertical", command=dsp_result2.yview)
textHsb2 = tk.Scrollbar(textContainer2, orient="horizontal", command=dsp_result2.xview)
dsp_result2.configure(yscrollcommand=textVsb2.set, xscrollcommand=textHsb2.set)
dsp_result2.grid(row=0, column=0, sticky='nsew')
textVsb2.grid(row=0, column=1, sticky='ns')
textHsb2.grid(row=1, column=0, sticky='ew')
textContainer2.grid_columnconfigure(0, weight=1)
textContainer2.grid_rowconfigure(0, weight=1)

frm_basic.grid(row=0, column=0, columnspan=2)
frm_buttons.grid(row=2, column=0, columnspan=2, pady=10)
textContainer1.grid(row=3, column=0, padx=5)
textContainer2.grid(row=3, column=1, padx=5)
recordContainer.grid(row=0, column=2, rowspan=6, sticky='e')  

dsp_result1.tag_configure('highlight', foreground='green', underline=1)
dsp_result1.tag_bind('highlight', '<Button-1>', on_click)

dsp_result2.tag_configure('highlight', foreground='green', underline=1)
dsp_result2.tag_bind('highlight', '<Button-1>', on_click)

mainWindow.mainloop()
