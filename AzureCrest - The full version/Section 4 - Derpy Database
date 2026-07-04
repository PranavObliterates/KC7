# Section 4: Derpy Database

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

---

## Question 1

This Twitter user, also known as "Hutch", co-authored the paper that introduced the Cyber Kill Chain to information security. (enter their @ username)

### Notes

- Basic OSINT.

### Answer

`@killchain`

---

## Question 2

The seven steps of the Cyber Kill Chain enhance visibility into an attack and enrich an analyst’s understanding of an adversary’s tactics, techniques and procedures.

What is the first step of the Cyber Kill Chain?

### Answer

`Reconnaissance`

---

## Question 3

Let's dive deeper into the threat actor's initial reconnaissance efforts to better understand what the attacker was seeking.

How many records are there of the threat actor browsing the Azure Crest Hospital's website?

### KQL Query

```kql
let bad_ips =
ProcessEvents
| where process_commandline contains "-ssh"
| distinct tostring(split(process_commandline, " ")[4]);

InboundNetworkEvents
| where url contains "azurecresthospital.med"
| where src_ip in (bad_ips)
| count
```

### Answer

`32`

---

## Question 4

The threat actor apparently learned A LOT from doing research on Azure Crest's website. First they found about some major personnel changes at the hospital.

These changes came as part of the CFO's promise to save money.

What article did they read about personnel changes at the hospital? (provide full url)

### KQL Query

```kql
InboundNetworkEvents
| where user_agent == "Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00"
| where url contains "azurecresthospital.med"
```

### Notes

- Review the browsing activity manually and identify the article viewed by the threat actor.

### Answer

`https://azurecresthospital.med/news/half-of-it-department-fired`

---

## Question 5

Following the personnel changes, Azure Crest's CFO hired her buddy to fill in the gaps.

Which employee was hired as part of an effort to reduce costs?

### KQL Query

```kql
Employees
| where name has "Roy"
```

### Notes

- Roy Trenneman was identified from the article reviewed in the previous step.

### Answer

`Roy Trenneman`

---

## Question 6

This new employee went right to work on figuring out how to save money. His suggestion, touted and published as research on the Azure Crest Hospital website, was to have Azure Crest bring their technology in-house.

Narrator Note: It was actually a VERY BAD idea

What article did Azure Crest publish about building one's own stuff instead of paying for it? (provide the full url)

### Notes

- Search the Azure Crest research article URLs.

### Answer

`https://azurecresthospital.med/news/research/why-pay-for-expensive-erp-systems-when-you-can-run-your-own`

---

## Question 7

While conducting reconnaissance, the threat actor also tried to get information about the juicy targets they were after.

What specific type of medical records was the Threat Actor attempting to access on Azure Crest Hospital’s internal share?

### Notes

- The threat actor browsed:
  `https://azurecresthospital.med/internal_share/medical_records/pediatric`
- The answer is derived from the record category in the URL.

### Answer

`pediatric`

---

## Question 8

After researching two employees at Azure Crest Hospital, the threat actor focused their efforts on one employee in particular.

Which employee did the threat actor ultimately decide to target?

### Notes

- Review browsing activity related to employee research.
- The threat actor viewed more content related to Roy Trenneman than Penny.

### Answer

`Roy Trenneman`

---

## Question 9

What is that employee's role?

### KQL Query

```kql
Employees
| where name has "Roy Trenneman"
| project role
```

### Answer

`Database Administrator`

---

## Question 10

What is the timestamp of the email that the threat actor sent to that employee?

### KQL Query

```kql
Email
| where recipient == "roy_trenneman@azurecresthospital.med"
| where link contains ".docm"
```

### Answer

`2024-03-04T10:52:18Z`

---

## Question 11

Did that employee click on the link? (yes/no)

### KQL Query

```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.2"
| where url contains "http://unhealthyrecordsystems.tech/images/images/New_Healthcare_Protocols.docm"
```

### Answer

`yes`

---

## Question 12

Hooooo boy 🤦🏽‍♂️

What is the timestamp for when the docm file was created on Roy's machine?

### KQL Query

```kql
FileCreationEvents
| where filename == "New_Healthcare_Protocols.docm"
| where hostname == "SUPER-DB-SERVER-9000"
| project timestamp
```

### Answer

`2024-03-04T11:28:57Z`

---

## Question 13

What is the name of the first malicious file created by the threat actor in the user's Temp folder?

### KQL Query

```kql
FileCreationEvents
| where hostname == "SUPER-DB-SERVER-9000"
| where path contains "temp"
| sort by timestamp asc
```

### Notes

- Review the earliest file creation events within the Temp directory.

### Answer

`dbhunter.exe`

---

## Question 14

What types of files does dbhunter.exe search for upon execution? (enter any one of them)

### KQL Query

```kql
ProcessEvents
| where hostname contains "SUPER-DB-SERVER-9000"
| where process_commandline contains "dbhunter.exe"
```

### Notes

- The command line references several database file types.
- Examples include:
  - `.db`
  - `.sql`
  - `.mdb`

### Answer

`.db`

---

## Question 15

After compressing a series of files for exfiltration, the threat actor secures them with a password.

What password is used to encrypt the compressed file containing Roy's meme collection?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "meme"
```

### Notes

- Review the process command line associated with the meme archive.

### Answer

`mommawemadeit`

---

## Question 16

The execution of UrTottalyPwned.bat triggers the encryption of database files.

What extension has been added to the files to indicate that they have been encrypted?

### KQL Query

```kql
FileCreationEvents
| where hostname == "SUPER-DB-SERVER-9000"
```

### Notes

- Search for the `.bat` file activity.
- Review subsequent file creation events.
- Identify the common extension appended to encrypted files.

### Answer

`.scholopendra`

---

## Question 17

A command was executed to modify registry settings, altering the desktop wallpaper for all user profiles. This change indicates that the files throughout the database had been encrypted by the threat actor.

What is the name of the new wallpaper?

### KQL Query

```kql
ProcessEvents
| where hostname == "SUPER-DB-SERVER-9000"
```

### Notes

- Search for the `.bat` execution activity.
- Review subsequent commands that modify wallpaper-related registry settings.

### Answer

`ItWentWrong.jpg`

---