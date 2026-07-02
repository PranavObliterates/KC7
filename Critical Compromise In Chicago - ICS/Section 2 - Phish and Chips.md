# Section 2: Phish and Chips

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

---

## Question 1

The investigation is about to get tougher.

Enter Phish and Chips to continue.

### Answer

`Phish and Chips`

---

## Question 2

Which sender address did the threat actor use to target the highest number of employees?

### KQL Query

```kql
Email
| where link contains "Urgent"

Email
| where subject == "Critical: Grid Security Update Required"

Email
| where recipient == "joseph_eisenman@chicagopowergrid.com"

Email
| where recipient == "elizabeth_nunmaker@chicagopowergrid.com"

Email
| where link contains "http://citygridsolutions.net/search/images/published/login.html"

Email
| where subject == "[EXTERNAL] Critical: Severe Security Breach Detected - Immediate Action Required"
```

### Notes

- Search emails containing "Urgent" in the link.
- Copy the subject and search for other emails with the same subject.
- Identify accounts sending phishing emails with matching subjects.
- Compare links used in the phishing emails.
- Search for additional emails using the same phishing link.
- Pivot on the common phishing subject.
- Identify the sender appearing most frequently across the phishing campaign.

### Answer

`thresher_libero@hotmail.com`

---

## Question 3

What threat actor controlled IP was used to log in to the most accounts?

### KQL Query

```kql
PassiveDns
| where domain in ("citygridsolutions.net", "chicagogridupdates.com")

AuthenticationEvents
| where src_ip in ("87.250.252.242", "104.244.42.129")
| where result contains "success"
| summarize count() by src_ip
```

### Answer

`87.250.252.242`

---

## Question 4

The attacker performed reconnaissance on two SCADA operators but chose to target only one.

Which SCADA operator was not targeted?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip in ("87.250.252.242", "104.244.42.129")
| where url contains "Operator"
```

### Answer

`Wade Wells`

---

## Question 5

Which compromised employee's account was used to send the first phishing email to the final victim?

### KQL Query

```kql
let compro_accs =
AuthenticationEvents
| where src_ip in ("87.250.252.242", "104.244.42.129")
| distinct username;

let compro_mails =
Employees
| where username in (compro_accs)
| distinct email_addr;

Email
| where link contains ".zip"
| where sender in (compro_mails)
```

### Answer

`Joseph Eisenman`

---

## Question 6

How many employees in total received phishing emails during the attack?

### KQL Query

```kql
Email
| where link has_any ("chicagogridupdates.com", "citygridsolutions.net", "infrastructurewatch.org")
| distinct recipient
```

### Notes

Resolve the attacker-controlled domains through PassiveDns to identify additional phishing infrastructure.

### Answer

`12`

---

## Question 7

What command was used to enumerate the list of domain controllers within the network?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "nltest"
```

### Notes

Used to locate domain controller enumeration activity.

### Answer

`nltest /dclist:chicagogrid.local`

---

## Question 8

What file path did the attacker use to store the results of their password file search?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "password"
```

### Notes

Review commands containing "password" and identify referenced text files.

### Answer

`C:\ProgramData\Password_Files.txt`

---

## Question 9

What upcoming corporate event did the threat actor browse on the chicagopowergrid.com website?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip in ("87.250.252.242", "104.244.42.129")
```

### Notes

Review browsing activity from attacker-controlled IPs and inspect visited URLs.

### Answer

`karaoke night`

---

## Question 10

The attacker attempted to cover their tracks by clearing specific event logs.

What command was used to clear the System event log?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "wevtutil"
```

### Notes

Identify the command targeting the System event log.

### Answer

`wevtutil cl System`
