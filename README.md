# NetRay

Lightweight swiss army knife type utility to perform various quick checks on domains and IP addresses.
Aim of the project is to combine common information gathering tools such as WHOIS with integration with various data providers through API, and enable analyst to avoid having to access multiple web based interfaces.

NetRay allows you to gather in one place data from the infrastructure analysis services - Passive Total, Shodan, and Censys - and facilitate the transfer of indicators from one service to another to another. The operation of the application will be most easily explained by discussing the various elements of the interface:

![NetRay interface](https://github.com/lawsecnet/NetRay/blob/main/readme_files/interface.png)

1. At the top, you'll find entry fields in which you respectivelly enter the indicator you're interested in and the API keys for querying Passive Total, Shodan, and Censys. API querying functions work independently of each other so if we will use only on or two of the modules you do not need to enter all the keys.

2. In the upper right corner there is a display which stores all the indicators we searched for. In this way we always have visibility into what path we went through to get to the current result.

3. Below are the buttons that activate the lookups. Thus, we have access to:

* WHOIS query using the Python IPWhois or Python Whois module - depending on whether we indicate an IP address or a domain.

* Searching passive DNS results from the Passive Total database.

* Display host information from Shodan. Since this function works on IP addresses, in the case of a domain, the application will perform a reverse DNS query using the socket library.

* Searching in the Shodan database and displaying the results.

* Display the properties of the TLS certificate from the Censys database. Use SHA256 certificate hash as a search term.

* Searching the Censys database for certificates. Here you do not have to limit ourselves to domains, IP addresses, and hashes as seach terms.

* Display information about the host from the Censys database. A function analogous to the Shodan functionality.

* Clearing the record of searched indices.

* Display Switcher. Since depending on how we work we may want to have some results available all the time I have not introduced any automation in terms of data display switching - if the switch is active the data will be displayed on the left, if not then on the right.

4. Below you will find two windows in which search results will be displayed. To make things easier, the application detects IP addresses, domains, SHA256 hashes, JARM hashes, email addresses, and AS numbers in the results. These elements are highlighted, and clicking on them places them in the search entry box.


# Demo

![NetRay demo](https://github.com/lawsecnet/NetRay/blob/main/readme_files/nrdemo.gif)
