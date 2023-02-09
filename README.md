# Introduction

Routector is designed to use Criminal IP to detect vulnerable routers, then leverage information from detected backdoors/vulnerabilities to remotely access the router management panel, and modify DNS server settings.



# Prerequisites

* criminalip.io API Key

   Get it [here](https://www.criminalip.io/)



# Installation

Clone repository:

```
$ git clone https://github.com/Jaxon1111/routector.git
```

```
$ cd routector
```

```
$ python3 -m venv .venv
$ source .venv/bin/activate
```

```
$ pip3 install -r requirements.txt
```



# Getting started

```
$ python3 routector.py --K [your-criminalip-api-key]
```


# Optional Arguments
| Flag                  | MetaVar              | Usage                                                        |
| --------------------- | -------------------- | ------------------------------------------------------------ |
| `-K/--key`           | **API key**          | python3 routector.py -K abcdefg... |




# Usage
* Use the 'search' command to find and view router information.
* Use the 'scan' command to scan the backdoor on the destination router.
* Use the 'map' command to map the network of devices connected to vulnerable routers.
* Use the 'pharm' command to change the DNS settings of the vulnerable router.
* Use the 'targets' command to determine the potential targets found in this session.
* Use the 'backdoors' command to determine which router has the backdoor verified.
* Use the 'devices' command to check all devices connected to the vulnerable router.



# Issue / Feedback etc.

Thank you for using routector! If you have any issues/feedback you want to tell me, just leave a comment or pop me an email. 

You're always welcome to add a sameple pull request added to example_quiries.py.
