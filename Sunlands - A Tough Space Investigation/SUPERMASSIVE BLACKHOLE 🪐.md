# SECTION 1: SUPERMASSIVE BLACKHOLE 🪐

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

You notice some security alerts for a file that appears to contain details on the blueprints of the Sunlands' energy grid. Paste the filename.

### KQL Query
```kql
SecurityAlerts
| where description contains "energy"
```

### Notes

Check the first alert description.

### Answer

`EnergyGrid-Blueprints.docx`

---

## Question 2

Which host did the alert from Q1 detect the suspicious file on?

### Answer

`NKIG-DESKTOP`

---

## Question 3

Which employee does the host from Q2 belong to?

### KQL Query
```kql
Employees
| where hostname == "NKIG-DESKTOP"
```

### Answer

`Monica Aguila`

---

## Question 4

The attacker sent the suspicious file to that employee from what email address?

### KQL Query
```kql
Email
| where recipient == "monica_aguila@space.gov.su"
| where sender !contains "@space.gov.su"
| where link contains ".docx"
```

### Answer

`urgent@verizon.com`

---

## Question 5

Look at the email message from Q4. The webmail service of the other attacker email address is headquartered in what country?

### Notes

The reply-to email is `energygrid@protonmail.com`. ProtonMail is headquartered in Switzerland.

### Answer

`Switzerland`

---

## Question 6

What domain did the victim download the file from?

### KQL Query
```kql
Email
| where recipient == "monica_aguila@space.gov.su"
| where sender !contains "@space.gov.su"
| where link contains ".docx"
| extend domain = tostring(parse_url(link).Host)
| project domain
```

### Answer

`renewablesolutionsgriddefender.com`

---

## Question 7

What is the name of the process through which the suspicious file was downloaded?

### KQL Query
```kql
FileCreationEvents
| where filename == "EnergyGrid-Blueprints.docx"
| where hostname == "NKIG-DESKTOP"
| project process_name
```

### Answer

`Edge.exe`

---

## Question 8

How many unique IP addresses does the domain from Q6 resolve to?

### KQL Query
```kql
PassiveDns
| where domain == "renewablesolutionsgriddefender.com"
| distinct ip
| count
```

### Answer

`10`

---

## Question 9

How many domains do the IP addresses from Q8 resolve to?

### KQL Query
```kql
let ips =
PassiveDns
| where domain == "renewablesolutionsgriddefender.com"
| distinct ip;
PassiveDns
| where ip in (ips)
| distinct domain
```

### Answer

`11`

---

## Question 10

How many employees visited the domains from Q9?

### KQL Query
```kql
let ips =
PassiveDns
| where domain == "renewablesolutionsgriddefender.com"
| distinct ip;
let doms =
PassiveDns
| where ip in (ips)
| distinct domain;
OutboundNetworkEvents
| where url has_any (doms)
| distinct src_ip
| count
```

### Answer

`39`

---

## Question 11

How many unique files were downloaded from the domains from Q9?

### KQL Query
```kql
let ips =
PassiveDns
| where domain == "renewablesolutionsgriddefender.com"
| distinct ip;
let doms =
PassiveDns
| where ip in (ips)
| distinct domain;
OutboundNetworkEvents
| where url has_any (doms)
| extend paths = tostring(parse_url(url).Path)
| extend files = tostring(parse_path(paths).Filename)
| summarize count() by files
```

### Answer

`5`

---

## Question 12

Looking at the files found in Q11, which one was downloaded the most?

### Answer

`GridDefender_Technical_Doc.xlsx`

---

## Question 13

Let's take a look at the employees who downloaded the files from question 11.

Which role is seen the most?

### KQL Query
```kql
let ips =
PassiveDns
| where domain == "renewablesolutionsgriddefender.com"
| distinct ip;
let doms =
PassiveDns
| where ip in (ips)
| distinct domain;
let down_files =
OutboundNetworkEvents
| where url has_any (doms)
| extend paths = tostring(parse_url(url).Path)
| extend files = tostring(parse_path(paths).Filename)
| project files;
let emps =
FileCreationEvents
| where filename in (down_files)
| distinct username;
Employees
| where username in (emps)
| summarize count() by role
```

### Answer

`Intern`

---

## Question 14

What is the name of the employee who first downloaded one of the files from question 11?

### KQL Query
```kql
let ips =
PassiveDns
| where domain == "renewablesolutionsgriddefender.com"
| distinct ip;
let doms =
PassiveDns
| where ip in (ips)
| distinct domain;
let down_files =
OutboundNetworkEvents
| where url has_any (doms)
| extend paths = tostring(parse_url(url).Path)
| extend files = tostring(parse_path(paths).Filename)
| project files;
FileCreationEvents
| where filename in (down_files)
```

### Notes

Sort by timestamp to identify the earliest download.

```kql
Employees
| where username == "wiwiemer"
```

### Answer

`Wilbert Wiemer`

---

## Question 15

TDMtRDlOeDFYczg9aT91cGduai96YnAucm9oZ2hibC5qamovLzpmY2dndQ==

### Notes

Base64 → Reverse → ROT13

### Answer

`https://www.youtube.com/watch?v=8fK1kA9Q-3Y`
