# Section 3: The Phisher's Net

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

In the previous section, we identified a series of suspicious files with a healthcare theme. Let's widen our investigation to see if other employees were targeted with these suspicious files.

How many Azure Crest employees received emails containing a link to the previously identified (.docm) files?

### KQL Query

```kql
Email
| where link contains ".docm"
| distinct recipient
```

### Answer

`40`

---

## Question 2

Aight, that's a lot of emails. I guess the water cooler will have to wait 😭

Let's get to the bottom of this!

How many distinct subjects did the threat actors use in this batch of emails?

### KQL Query

```kql
Email
| where link has_any ("New_Healthcare_Protocols.docm", "Pediatric_Care_Update.docm")
| extend clean_subject = replace_string(subject,"RE: ", "")
| extend clean_subject = replace_string(clean_subject,"FW: ", "")
| distinct clean_subject
```

### Answer

`7`

---

## Question 3

How many distinct links did the threat actors use in this batch of emails?

### KQL Query

```kql
Email
| where link has_any ("New_Healthcare_Protocols.docm", "Pediatric_Care_Update.docm")
| distinct link
```

### Answer

`17`

---

## Question 4

Let's make note of the domains the threat actors used. This information may be useful later.

How many distinct domains were used in this batch of emails?

### KQL Query

```kql
Email
| where link has_any ("New_Healthcare_Protocols.docm", "Pediatric_Care_Update.docm")
| extend domain = tostring(parse_url(link).Host)
| distinct domain
```

### Answer

`4`

---

## Question 5

Alright, we know the threat actor sent a lot of emails our way. We want to know if they had any success. If we are lucky, everyone will have recalled their cyberawareness training, and no one will have clicked on these shady links.

How many employees clicked on the email links?

### KQL Query

```kql
let who_got = 
Email
| where link has_any ("New_Healthcare_Protocols.docm", "Pediatric_Care_Update.docm")
| distinct recipient;

let who_got_ip =
Employees
| where email_addr in (who_got)
| distinct ip_addr;

let all_links = 
Email
| where link has_any ("New_Healthcare_Protocols.docm", "Pediatric_Care_Update.docm")
| distinct link;

OutboundNetworkEvents
| where src_ip in (who_got_ip) and url in (all_links)
| distinct src_ip
```

### Answer

`37`

---

## Question 6

😭😭😭😭 OK, so maybe there was a click or two, we can still recover.

How many records are there for either of these files being on Azure Crest employee computers?

### KQL Query

```kql
FileCreationEvents
| where filename has_any ("New_Healthcare_Protocols.docm", "Pediatric_Care_Update.docm")
```

### Answer

`38`

---

## Question 7

What is the timestamp for the first time one of these files was created?

### KQL Query

```kql
FileCreationEvents
| where filename has_any ("New_Healthcare_Protocols.docm", "Pediatric_Care_Update.docm")
| sort by timestamp asc
```

### Notes

- Sort the results by timestamp in ascending order and inspect the first record.

### Answer

`2024-03-01T11:58:33Z`

---

## Question 8

Let's take a closer look at the first computer that downloaded the suspicious file.

What is the name of the file that is created after the suspicious file is downloaded?

### KQL Query

```kql
ProcessEvents
| where hostname == "P3EX-DESKTOP"
```

### Notes

- Review the process activity on the first compromised host.
- Inspect the third log entry.

### Answer

`heartburn.zip`

---

## Question 9

What is the directory path that contains this new file?

### Notes

- Use the directory path only.
- Do not include the filename in the answer.

### Answer

`C:\ProgramData\Heartburn\`

---

## Question 10

On that machine, how many additional files are created in the same directory?

### KQL Query

```kql
FileCreationEvents
| where hostname == "P3EX-DESKTOP"
| where path contains @"C:\ProgramData\Heartburn\"
```

### Notes

- Review files created in the Heartburn directory.
- Additional files observed:
  - anydesk.exe
  - putty.exe
  - secretsdump.exe

### Answer

`3`

---

## Question 11

What command was used to extract the additional files from the zip file into the same directory where it was located?

### KQL Query

```kql
ProcessEvents
| where hostname == "P3EX-DESKTOP"
| where process_commandline contains @"C:\ProgramData\Heartburn"
```

### Notes

- Review commands referencing the Heartburn directory.
- Inspect the second command.

### Answer

`cmd.exe /c Expand-Archive -Path C: \ProgramData\heartburn.zip -DestinationPath C:\ProgramData\Heartburn`

---

## Question 12

What is the IP address that putty.exe uses to establish it's SSH connection?

### KQL Query

```kql
ProcessEvents
| where hostname == "P3EX-DESKTOP"
| where process_commandline contains @"C:\ProgramData\Heartburn"
```

### Notes

- Review commands referencing the Heartburn directory.
- Inspect the third command.

### Answer

`93.142.203.80`

---

## Question 13

What does the acronym SSH stand for?

### Notes

- Identified from the SSH connection activity.

### Answer

`Secure Shell`

---

## Question 14

How many unique IP addresses were used to initiate similar SSH connections?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "-ssh"
| distinct tostring(split(process_commandline, " ")[4])
```

### Answer

`17`

---

## Question 15

What username is used to initiate the SSH connection?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "-ssh"
```

### Notes

- Review the value that appears after the `-l` parameter.

### Answer

`have_ya_tried`

---

## Question 16

What is the password used to initiate the SSH connection?

### Notes

- Review the value that appears after the `-pw` parameter.

### Answer

`turning_it_off_and_on_again`

---

## Question 17

Discovery commands are often run by an attacker to collect information about the target system or network.

How many of these commands were run on the victim's computer?

### KQL Query

```kql
ProcessEvents
| where hostname == "P3EX-DESKTOP"
```

### Notes

- Search for `whoami`, which is typically one of the first discovery commands executed.
- Review subsequent discovery-related commands executed on the host.

### Answer

`5`

---

## Question 18

Just as you're about to continue investigating, the sweaty and very flustered IT Director barges in with an urgent tone, firing off questions:

"Wait a minute! Is it over yet? People keep asking me questions! Have you found who is responsible yet? Are they still in the network? What's taking so long? Is it the darkweb cybercriminals? I heard about darkweb cybercriminal hackers targeting healthcare companies. How many of our employee computers have been hacked? How bad is it?”

You inwardly sigh knowing you'll need to address the Director's most immediate concern before you can finish your investigation.

How many of our employee computers have been compromised?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "-ssh"
| distinct hostname
```

### Answer

`35`

---