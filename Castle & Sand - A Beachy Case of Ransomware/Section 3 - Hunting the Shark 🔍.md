# Section 3: Hunting the Shark 🔍

## Table of Contents
- [Question 1](#question-1)
- [Question 2](#question-2)
- [Question 3](#question-3)
- [Question 4](#question-4)
- [Question 5](#question-5)
- [Question 6](#question-6)
- [Question 7](#question-7)
- [Question 8](#question-8)
- [Question 9](#question-9)
- [Question 10](#question-10)
- [Question 11](#question-11)
- [Question 12](#question-12)
- [Question 13](#question-13)
- [Question 14](#question-14)
- [Question 15](#question-15)

---

## Question 1

Oh no! The ransomware gang sent the Castle&Sand CEO a voicemail. Listen to it.

How many hours does Castle&Sand have before the gang releases the information?

### Notes

- The voicemail states that Castle&Sand has **72 hours** before the stolen information is released.

### Answer

`72`

---

## Question 2

What do the ransomware gang call themselves?

### Notes

- The voicemail references the group as:
  `#Sharkboyz`

### Answer

`sharkboyz`

---

## Question 3

What Mitre Technique is aligned with what this group did on Castle&Sand systems?

### Notes

- The ransomware activity aligns with the MITRE ATT&CK technique:
  **Data Encrypted for Impact**

### Answer

`T1486`

---

## Question 4

Let's search for the email domain used in the ransom note.

What is the ZIP code of their headquarters?

### Answer

`10016`

---

## Question 5

What country is this email service located in?

### Answer

`US`

---

## Question 6

Let's look at the IP addresses from Section 2, Q18 using MaxMind GeoIP2.

How many continents total are these IP addresses from?

### KQL Query

```kql
PassiveDns
| where domain == "jawfin.com"
| distinct ip
```

### Notes

- Copy the IP addresses returned by the query.
- Look them up using MaxMind GeoIP2:
  `https://www.maxmind.com/en/geoip-web-services-demo`
- Results show:
  - 3 IPs in North America
  - 2 IPs in Europe
  - 1 IP in South America

### Answer

`3`

---

## Question 7

Use search.censys.io to look up the IP address found in Section 2, Q19.

What is the Autonomous System (AS) number for the IP address?

### Notes

- Lookup the IP from Section 2 Question 19 using Censys.

### Answer

`3215`

---

## Question 8

Look at the IPs from Section 2, Q20.

Which one is assigned to a University?

### KQL Query

```kql
PassiveDns
| where domain == "sharkfin.com"
| distinct ip
```

### Notes

- Perform ASN/organization lookups on the returned IPs.
- One resolves to **Loyola Marymount University**.

### Answer

`157.242.169.232`

---

## Question 9

Look at the emails from Section 2, Q28.

Which email address is associated with a company outside of the United States?

### KQL Query

```kql
let bad_emailaddr = 
Email
| where sender == "legal.sand@verizon.com"
| where recipient contains "@castleandsand.com"
| distinct reply_to;
Email
| where sender in (bad_emailaddr) or reply_to in (bad_emailaddr)
```

### Notes

- Review the sender and reply-to domains.
- Domains observed include:
  - verizon.com
  - hotmail.com
  - aol.com
  - yandex.com
- Yandex is operated by a Russian company and is outside the United States.

### Answer

`urgent_urgent@yandex.com`

---

## Question 10

For the tool found in Section 2, Q41, what is the MITRE ID for that specific software?

### Notes

- The tool identified in Section 2 Question 41 is:
  `mimikatz.exe`
- MITRE ATT&CK Software ID for Mimikatz:

### Answer

`S0002`

---

## Question 11

For the tool found in Section 2, Q41.

What is the MITRE ID for that type of technique that this tool is typically used for?

### Notes

- Mimikatz is commonly used for:
  `OS Credential Dumping`

### Answer

`T1003`

---

## Question 12

Take the filenames from Section 2, Q45.

How many unique SHA256 hashes are found in Castle&Sand's environment with these filenames?

### KQL Query

```kql
let bad_emailaddr = 
Email
| where sender == "legal.sand@verizon.com"
| where recipient contains "@castleandsand.com"
| distinct reply_to;
let bad_files =
Email
| where sender in (bad_emailaddr) or reply_to in (bad_emailaddr)
| extend paths = tostring(parse_url(link).Path)
| extend files = tostring(parse_path(paths).Filename)
| distinct files;
let bad_hosts =
FileCreationEvents
| where filename in (bad_files)
| distinct hostname;
let bad_parents =
ProcessEvents
| where hostname in (bad_hosts)
| where timestamp > datetime(2023-05-25T16:43:20.000Z)
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (bad_parents)
| summarize count() by parent_process_hash
```

### Answer

`9`

---

## Question 13

How many were flagged as malicious on VirusTotal?

### Notes

- Only one hash was not flagged as malicious:
  `4874d336c5c7c2f558cfd5954655cacfc85bcfcb512a45fb0ff461ce9c38b86d`

### Answer

`8`

---

## Question 14

Which file hash was reported by the security community as the ransomware's encrypted payload?

### Notes

- The following hash was reported by a security community user (`rivitna`) as the ransomware encrypted payload.

### Answer

`82a7241d747864a8cf621f226f1446a434d2f98435a93497eafb48b35c12c180`

---

## Question 15

For Section 2, Q46, what ransomware family uses a command similar to this process execution?

### Notes

- Research the observed command line and compare it to known ransomware execution patterns.
- The closest matching ransomware family is:

### Answer

`Bablock`

---