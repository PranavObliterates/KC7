# Section 2: Shark Attack! 🦈

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
- [Question 19](#question-19)
- [Question 20](#question-20)
- [Question 21](#question-21)
- [Question 22](#question-22)
- [Question 23](#question-23)
- [Question 24](#question-24)
- [Question 25](#question-25)
- [Question 26](#question-26)
- [Question 27](#question-27)
- [Question 28](#question-28)
- [Question 29](#question-29)
- [Question 30](#question-30)
- [Question 31](#question-31)
- [Question 32](#question-32)
- [Question 33](#question-33)
- [Question 34](#question-34)
- [Question 35](#question-35)
- [Question 36](#question-36)
- [Question 37](#question-37)
- [Question 38](#question-38)
- [Question 39](#question-39)
- [Question 40](#question-40)
- [Question 41](#question-41)
- [Question 42](#question-42)
- [Question 43](#question-43)
- [Question 44](#question-44)
- [Question 45](#question-45)
- [Question 46](#question-46)
- [Question 47](#question-47)
- [Question 48](#question-48)

---

## Question 1

What email address did the threat actor provide to Castle&Sand to communicate with them?

### Notes

- View the ransom note image:
  `https://kc7photos-cfhbcabpaxb2f8fn.z03.azurefd.net/manualphotos/sharknado_ransom.png`

### Answer

`sharknadorules_gang@onionmail.org`

---

## Question 2

What is the unique decryption ID?

### Answer

`SUNNYDAY123329JA0`

---

## Question 3

Always be sure to determine if the data is sensitive to the company. You have to make sure you protect sensitive information, including all of the information in the Castle&Sand database.

Should this be something you post publicly about? Yes or no?

### Answer

`No`

---

## Question 4

The ransom note filename was called PAY_UP_OR_SWIM_WITH_THE_FISHES.txt.

How many notes appeared in Castle&Sand's environment?

### KQL Query

```kql
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname
```

### Answer

`774`

---

## Question 5

Let's get a sense of the scope of impact!

How many distinct hostnames had the ransom note?

### KQL Query

```kql
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname
```

### Answer

`774`

---

## Question 6

Let's take the list of unique hostnames and search them across the Employees table.

How many distinct employee roles were affected by the ransomware attack?

### KQL Query

```kql
let compro_hosts = 
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (compro_hosts)
| distinct role
```

### Answer

`18`

---

## Question 7

Well that's concerning! There are some executives hit here, but what we should be worried about are the IT roles first.

They typically would have more administrative privileges on the Castle&Sand Network.

How many unique hostnames belong to IT employees?

### KQL Query

```kql
let compro_hosts = 
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (compro_hosts)
| where role has "IT"
```

### Answer

`25`

---

## Question 8

One of the IT employees has an IP address that ends in .46.

What is that employee's name?

### KQL Query

```kql
let compro_hosts = 
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (compro_hosts)
| where role has "IT"
| where ip_addr endswith ".46"
```

### Answer

`Simeon Kakpovi`

---

## Question 9

Let's take the unique hostnames that had the ransom note and search them across our SecurityAlerts.

How many security alerts involved the different hosts?

### KQL Query

```kql
let compro_hosts = 
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
SecurityAlerts
| where description has_any (compro_hosts)
```

### Answer

`652`

---

## Question 10

How many Security Alerts reference the hostnames of helpdesk employees that received ransom notes?

### KQL Query

```kql
let compro_hosts = 
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
let helpdesk_hosts = 
Employees
| where hostname in (compro_hosts)
| where role contains "IT Helpdesk"
| distinct hostname;
SecurityAlerts
| where description has_any (helpdesk_hosts)
```

### Answer

`27`

---

## Question 11

Much better. We can work with this smaller number!

Let's look for any anomalies in the alerts that look different from the other alerts and might be shark-themed like the ransomware. You should find one.

Who owns the machine that was flagged on that alert? (provide their name)

### Notes

- Review alert descriptions manually.
- Look for a suspicious alert referencing:
  `Chomping-Schedule_Changes.xlsx`
- Alert description:
  `A suspicious file was quarantined on host 6S7W-MACHINE: Chomping-Schedule_Changes.xlsx`

### KQL Query

```kql
Employees
| where hostname == "6S7W-MACHINE"
```

### Answer

`Preston Lane`

---

## Question 12

A file was flagged in that alert.

When did the file appear on that user's machine? (copy and paste the full timestamp)

### KQL Query

```kql
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| where hostname == "6S7W-MACHINE"
```

### Answer

`2023-05-26T09:26:15Z`

---

## Question 13

What's the SHA256 hash of that file?

### KQL Query

```kql
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| where hostname == "6S7W-MACHINE"
| project sha256
```

### Answer

`71daa56c10f7833848a09cf8160ab5d79da2dd2477b6b3791675e6a8d1635016`

---

## Question 14

What application created that file?

### KQL Query

```kql
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| where hostname == "6S7W-MACHINE"
| project process_name
```

### Answer

`Firefox.exe`

---

## Question 15

Let's look for other files with that same name.

How many unique hosts had files with that exact name on their systems?

### KQL Query

```kql
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| distinct hostname
```

### Answer

`11`

---

## Question 16

Based on the application that created the file (see Question 14), it looks like the file may have come from the Internet. Let's search and figure out which domain it might have come from.

How many unique domains did employees download this file from?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "Chomping-Schedule_Changes.xlsx"
| extend unique_domains = tostring(parse_url(url).Host)
| distinct unique_domains
```

### Answer

`2`

---

## Question 17

Based on the employee we've been tracking from Question 11, which domain did they download the file from?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "Chomping-Schedule_Changes.xlsx"
| where src_ip == "10.10.2.1"
| extend unique_domains = tostring(parse_url(url).Host)
```

### Answer

`jawfin.com`

---

## Question 18

Now let's check which IPs the domain may have used before. Let's use the PassiveDns table.

How many unique IP addresses did the domain resolve to?

### KQL Query

```kql
PassiveDns
| where domain == "jawfin.com"
| distinct ip
```

### Answer

`6`

---

## Question 19

Which IP address is closest in time to when the file was created on the employee's machine?

### KQL Query

```kql
PassiveDns
| where domain == "jawfin.com"
```

### Notes

- Compare the Passive DNS timestamps with:
  `2023-05-26T09:26:15Z`
- Select the IP record closest in time.

### Answer

`193.248.75.126`

---

## Question 20

There was another domain found from Q16. How many unique IPs did that domain resolve to?

### KQL Query

```kql
PassiveDns
| where domain == "sharkfin.com"
| distinct ip
```

### Answer

`4`

---

## Question 21

Let's take all of the IP addresses from the two domains and search them against network events on Castle&Sand's website.

How many records returned from your query?

### KQL Query

```kql
let all_ips_we_get = 
PassiveDns
| where domain in ("sharkfin.com", "jawfin.com")
| distinct ip;
InboundNetworkEvents
| where src_ip in (all_ips_we_get)
```

### Answer

`39`

---

## Question 22

When was the first time we saw any of these actor IP addresses from Q21 against Castle&Sand's network?

### KQL Query

```kql
let all_ips_we_get = 
PassiveDns
| where domain in ("sharkfin.com", "jawfin.com")
| distinct ip;
InboundNetworkEvents
| where src_ip in (all_ips_we_get)
| sort by timestamp asc
```

### Answer

`2023-05-20T03:11:57Z`

---

## Question 23

Let's search the actor IPs against AuthenticationEvents to see if they logged into any user machines or email accounts.

How many records did you get back?

### KQL Query

```kql
let all_ips_we_get = 
PassiveDns
| where domain in ("sharkfin.com", "jawfin.com")
| distinct ip;
AuthenticationEvents
| where src_ip in (all_ips_we_get)
```

### Answer

`0`

---

## Question 24

Let's look for the malicious domains in Emails.

How many records did you get back?

### KQL Query

```kql
Email
| where link has_any ("sharkfin.com", "jawfin.com")
```

### Answer

`14`

---

## Question 25

When was the earliest email sent?

### KQL Query

```kql
Email
| where link has_any ("sharkfin.com", "jawfin.com")
| sort by timestamp asc
```

### Answer

`2023-05-25T16:33:09Z`

---

## Question 26

Who was the sender?

### KQL Query

```kql
Email
| where link has_any ("sharkfin.com", "jawfin.com")
| sort by timestamp asc
| project sender
```

### Answer

`legal.sand@verizon.com`

---

## Question 27

How many emails total did that sender send to Castle&Sand employees?

### KQL Query

```kql
Email
| where sender == "legal.sand@verizon.com"
| where recipient contains "@castleandsand.com"
```

### Answer

`23`

---

## Question 28

Take all of the distinct sender or reply_to emails from the last question.

How many emails total are associated with these email addresses?

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

### Answer

`40`

---

## Question 29

How many unique domains did the email addresses use in their emails?

### KQL Query

```kql
let bad_emailaddr = 
Email
| where sender == "legal.sand@verizon.com"
| where recipient contains "@castleandsand.com"
| distinct reply_to;
Email
| where sender in (bad_emailaddr) or reply_to in (bad_emailaddr)
| extend unique_domains = tostring(parse_url(link).Host)
| distinct unique_domains
```

### Answer

`6`

---

## Question 30

How many distinct IP addresses total were used by all of the domains identified in Q29?

### KQL Query

```kql
let bad_emailaddr = 
Email
| where sender == "legal.sand@verizon.com"
| where recipient contains "@castleandsand.com"
| distinct reply_to;
let all_bad_doms_in_mail =
Email
| where sender in (bad_emailaddr) or reply_to in (bad_emailaddr)
| extend unique_domains = tostring(parse_url(link).Host)
| distinct unique_domains;
PassiveDns
| where domain in (all_bad_doms_in_mail)
| distinct ip
```

### Answer

`15`

---

## Question 31

How many user accounts did these IPs log into?

### KQL Query

```kql
let bad_emailaddr = 
Email
| where sender == "legal.sand@verizon.com"
| where recipient contains "@castleandsand.com"
| distinct reply_to;
let all_bad_doms_in_mail =
Email
| where sender in (bad_emailaddr) or reply_to in (bad_emailaddr)
| extend unique_domains = tostring(parse_url(link).Host)
| distinct unique_domains;
let bad_ips = 
PassiveDns
| where domain in (all_bad_doms_in_mail)
| distinct ip;
AuthenticationEvents
| where src_ip in (bad_ips)
```

### Answer

`0`

---

## Question 32

Looking at these emails (from question 28), how many unique filenames were served by these domains?

### KQL Query

```kql
let bad_emailaddr = 
Email
| where sender == "legal.sand@verizon.com"
| where recipient contains "@castleandsand.com"
| distinct reply_to;
Email
| where sender in (bad_emailaddr) or reply_to in (bad_emailaddr)
| extend paths = tostring(parse_url(link).Path)
| extend files = tostring(parse_path(paths).Filename)
| distinct files
```

### Answer

`5`

---

## Question 33

How many files with these names were created on employee host machines?

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
FileCreationEvents
| where filename in (bad_files)
```

### Answer

`34`

---

## Question 34

When was the first file observed?

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
FileCreationEvents
| where filename in (bad_files)
| summarize min(timestamp)
```

### Answer

`2023-05-25T16:43:20Z`

---

## Question 35

Let's take the hosts from here and search for them in ProcessEvents.

How many records total are associated with the identified host machines from Q33?

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
ProcessEvents
| where hostname in (bad_hosts)
```

### Answer

`16391`

---

## Question 36

Using your query from Q35, set a new query where the timestamp is greater than the first time you saw the file in Q34.

How many records total do you have now?

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
ProcessEvents
| where hostname in (bad_hosts)
| where timestamp > datetime(2023-05-25T16:43:20.000Z)
```

### Answer

`5818`

---

## Question 37

Let's look at the first few records. There's some suspicious powershell activity that occurs near the beginning.

What IP address is referenced in that command?

### Notes

- Manually inspect the `process_commandline` field.
- Look for the suspicious PowerShell execution near the beginning of the timeline.

### Answer

`220.35.180.137`

---

## Question 38

Which host machine did the powershell activity execute on?

### Notes

- Identify the hostname associated with the first suspicious PowerShell execution.

### Answer

`CL8Q-LAPTOP`

---

## Question 39

There's a weird repeating command right before this activity.

What's the parent process of the first time this repeated activity occurs?

### Notes

- Prior to the PowerShell execution, there are three repeated `echo "hello"` commands.
- The first occurrence shows the parent process.

### Answer

`scvhost.exe`

---

## Question 40

What legitimate Windows process was this file trying to masquerade as?

### Notes

- The observed process is `scvhost.exe`.
- This is a typo-squatted version of a legitimate Windows process.

### Answer

`svchost.exe`

---

## Question 41

After the powershell activity there's evidence that a popular password cracking tool may have executed on a host machine. Take that file and search for how many times that tool may have ran on the Castle&Sand environment.

How many hosts had their passwords dumped?

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
ProcessEvents
| where hostname in (bad_hosts)
| where timestamp > datetime(2023-05-25T16:43:20.000Z)
| where process_commandline has "mimikatz.exe"
| distinct hostname
```

### Answer

`31`

---

## Question 42

Let's go back to the powershell activity from question 37.

How many hosts did that powershell command execute on?

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
ProcessEvents
| where hostname in (bad_hosts)
| where timestamp > datetime(2023-05-25T16:43:20.000Z)
| where process_commandline contains "powershell.exe -nop -w hidden -c"
```

### Answer

`31`

---

## Question 43

(BONUS HARD QUESTION)

How many unique IP addresses were used in these commands?

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
ProcessEvents
| where hostname in (bad_hosts)
| where timestamp > datetime(2023-05-25T16:43:20.000Z)
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| parse process_commandline with * "https://" unique_ip "/" *
| distinct unique_ip
```

### Answer

`14`

---

## Question 44

(BONUS HARD QUESTION)

Which of these IP addresses was seen the most?

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
ProcessEvents
| where hostname in (bad_hosts)
| where timestamp > datetime(2023-05-25T16:43:20.000Z)
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| parse process_commandline with * "https://" unique_ip "/" *
| summarize count() by unique_ip
| sort by count_
```

### Answer

`157.242.169.232`

---

## Question 45

Take the parent processes from Q42.

How many records total involved those processes?

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
```

### Answer

`62`

---

## Question 46

Let's look to see if any of these files are referenced in the command line.

How many records did you find?

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
| where process_commandline has_any (bad_parents)
```

### Answer

`1548`

---

## Question 47

When was the earliest time found in Q46?

### Notes

- Review the results from Question 46.
- Sort by timestamp ascending and identify the earliest record.

### Answer

`2023-06-09T19:43:58Z`

---

## Question 48

You remember that the encrypted files all had the extension '.sharkfin'. Search for that in created files.

When was the earliest time you saw these files?

### KQL Query

```kql
FileCreationEvents
| where filename contains ".sharkfin"
| summarize min(timestamp)
```

### Answer

`2023-06-09T19:43:48Z`

---