# Section 4: Sand in my 👁️👁️

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
- [Question 16](#question-16)
- [Question 17](#question-17)
- [Question 18](#question-18)

---

## Question 1

You've been informed by several threat intelligence analysts from other companies that Castle&Sand may have been targeted by a recent phishing campaign.

The threat actors used an email with Castle&Sand's name in it: `castleandsand_official@outlook.com`.

How many emails were sent from this email to Castle&Sand employees?

### KQL Query

```kql
Email
| where sender == "castleandsand_official@outlook.com"
| where recipient endswith "@castleandsand.com"
```

### Answer

`19`

---

## Question 2

There appears to be another email account.

How many emails total are referenced by these two email accounts?

### KQL Query

```kql
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
```

### Answer

`33`

---

## Question 3

How many unique domains are found in the links of these emails?

### KQL Query

```kql
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| extend unique_doms = tostring(parse_url(link).Host)
| distinct unique_doms
```

### Answer

`4`

---

## Question 4

Based on these domains, what type of attack did this threat actor conduct?

### Notes

- Review the training guide for the attack category associated with these malicious domains.

### Answer

`Drive-by Compromise`

---

## Question 5

How many distinct job roles were targeted by this type of attack?

### KQL Query

```kql
let target_reci =
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| distinct recipient;
Employees
| where email_addr in (target_reci)
| distinct role
```

### Answer

`13`

---

## Question 6

Let's take the targeted employees and look for all external IP addresses that authenticated to those users.

How many external IP addresses were used to successfully log into those user accounts?

### KQL Query

```kql
let target_reci =
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| distinct recipient;
let target_users =
Employees
| where email_addr in (target_reci)
| distinct username;
AuthenticationEvents
| where username in (target_users)
| where src_ip !contains "10.10"
| where result contains "success"
| distinct src_ip
```

### Answer

`43`

---

## Question 7

These IP addresses may have accessed email inboxes and downloaded data.

How many unique filenames were downloaded by these IP addresses?

### KQL Query

```kql
let target_reci =
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| distinct recipient;
let target_users =
Employees
| where email_addr in (target_reci)
| distinct username;
let ext_ips =
AuthenticationEvents
| where username in (target_users)
| where src_ip !contains "10.10"
| where result contains "success"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (ext_ips)
| where url has_all ("mail", "download=true")
| extend filenames = tostring(parse_urlquery(url).['Query Parameters']["output"])
| distinct filenames
```

### Answer

`14`

---

## Question 8

How many distinct IPs were involved in the stealing of downloaded data from the previous questions?

### KQL Query

```kql
let target_reci =
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| distinct recipient;
let target_users =
Employees
| where email_addr in (target_reci)
| distinct username;
let ext_ips =
AuthenticationEvents
| where username in (target_users)
| where src_ip !contains "10.10"
| where result contains "success"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (ext_ips)
| where url has_all ("mail", "download=true")
| distinct src_ip
```

### Answer

`9`

---

## Question 9

Based on the IPs from Q6, how many unique domains did they resolve to?

### KQL Query

```kql
let target_reci =
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| distinct recipient;
let target_users =
Employees
| where email_addr in (target_reci)
| distinct username;
let ips =
AuthenticationEvents
| where username in (target_users)
| where src_ip !contains "10.10"
| where result contains "success"
| distinct src_ip;
PassiveDns
| where ip in (ips)
| distinct domain
```

### Answer

`5`

---

## Question 10

Let's go back to the user accounts that may have been affected by the phishing campaign.

How many hosts have they logged into?

### KQL Query

```kql
let target_reci =
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| distinct recipient;
let target_users =
Employees
| where email_addr in (target_reci)
| distinct username;
let ext_ips =
AuthenticationEvents
| where username in (target_users)
| where src_ip !contains "10.10"
| where result contains "success"
| distinct src_ip;
AuthenticationEvents
| where username in (target_users)
| where result contains "success"
| distinct hostname
```

### Answer

`43`

---

## Question 11

Investigate the domains from Q9.

How many files are present on Castle&Sand systems that originated from these domains?

### KQL Query

```kql
let target_reci =
Email
| where sender == "castleandsandlegaldepartment@gmail.com"
   or sender == "castleandsand_official@outlook.com"
| distinct recipient;
let target_users =
Employees
| where email_addr in (target_reci)
| distinct username;
let ips =
AuthenticationEvents
| where username in (target_users)
| where src_ip !contains "10.10"
| where result contains "success"
| distinct src_ip;
let bad_doms =
PassiveDns
| where ip in (ips)
| distinct domain;
OutboundNetworkEvents
| where url has_any (bad_doms)
| extend paths = tostring(parse_url(url).Path)
| extend filenames = tostring(parse_path(paths).Filename)
| summarize count() by filenames
```

### Notes

Files observed:

- `store_updates.xlsx` → 1
- `employee.lnk` → 1
- `HR_Notes.pdf` → 3
- `Employee_Changes.xlsx` → 5
- `Work-Updates.docx` → 5

### Answer

`15`

---

## Question 12

Investigate what happens after these files are downloaded and find malicious activity.

How many unique malware filenames are created from these files?

### KQL Query (Identify Affected Hosts)

```kql
let affected_hosts =
FileCreationEvents
| where filename in (
    "Work-Updates.docx",
    "HR_Notes.pdf",
    "employee.lnk",
    "store_updates.xlsx",
    "Employee_Changes.xlsx"
)
| distinct hostname;

FileCreationEvents
| where hostname in (affected_hosts)
```

### KQL Query (Identify Malware Files)

```kql
let affected_hosts =
FileCreationEvents
| where filename in (
    "Work-Updates.docx",
    "HR_Notes.pdf",
    "employee.lnk",
    "store_updates.xlsx",
    "Employee_Changes.xlsx"
)
| distinct hostname;

FileCreationEvents
| where hostname in (affected_hosts)
| serialize
| extend filename_afterbadfiles = next(filename)
| where filename in (
    "Work-Updates.docx",
    "HR_Notes.pdf",
    "employee.lnk",
    "store_updates.xlsx",
    "Employee_Changes.xlsx"
)
| where filename_afterbadfiles !in (
    "Work-Updates.docx",
    "HR_Notes.pdf",
    "employee.lnk",
    "store_updates.xlsx",
    "Employee_Changes.xlsx"
)
| distinct filename_afterbadfiles
```

### Answer

`5`

---

## Question 13

How many of these files total are present on Castle&Sand systems?

### KQL Query

```kql
FileCreationEvents
| where filename in (
    "TSVIPSrv.dll",
    "1.exe",
    "i.exe",
    "wmi.dll",
    "procdump64.exe"
)
```

### Answer

`14`

---

## Question 14

How many distinct C2 servers are associated with the malware?

### KQL Query

```kql
ProcessEvents
| where parent_process_name has_any (
    "TSVIPSrv.dll",
    "1.exe",
    "i.exe",
    "wmi.dll",
    "procdump64.exe"
)
| where process_commandline contains "plink"
| distinct process_commandline
```

### Answer

`7`

---

## Question 15

Now it's kind of a choose your own adventure. You need to find out what this threat actor did at the very end.

When is the first time you see this final action by the threat actor? Copy & paste the full timestamp.

### KQL Query (Initial Investigation)

```kql
ProcessEvents
| where parent_process_name has_any (
    "TSVIPSrv.dll",
    "1.exe",
    "i.exe",
    "wmi.dll",
    "procdump64.exe"
)
```

### Notes

- Review the final commands executed by the attacker.
- On `NYEL-DESKTOP`, the attacker performs reconnaissance.
- Later process activity shows the use of **Invoke-DNSExfiltrator.ps1**.

### KQL Query (Confirm Final Action)

```kql
let compro_users =
ProcessEvents
| where parent_process_name in (
    "TSVIPSrv.dll",
    "1.exe",
    "i.exe",
    "wmi.dll",
    "procdump64.exe"
)
| distinct username;

let compro_hosts =
ProcessEvents
| where parent_process_name in (
    "TSVIPSrv.dll",
    "1.exe",
    "i.exe",
    "wmi.dll",
    "procdump64.exe"
)
| distinct hostname;

ProcessEvents
| where hostname in (compro_hosts)
| where username in (compro_users)
| distinct process_commandline
```

### KQL Query (Locate Earliest Execution)

```kql
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator.ps1"
```

### Answer

`2023-05-26T10:33:04Z`

---

## Question 16

What MITRE Technique is this aligned with?

### Notes

- The attacker's final action is DNS-based data exfiltration.

### Answer

`T1048`

---

## Question 17

How many hosts are affected by this action?

### KQL Query

```kql
let affected_hosts =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator.ps1"
| distinct hostname
```

### Answer

`14`

---

## Question 18

How many distinct job roles were affected by this action?

### KQL Query

```kql
let affected_hosts =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator.ps1"
| distinct hostname;

Employees
| where hostname in (affected_hosts)
| distinct role
```

### Answer

`5`

---