# Section 2: More Intel

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

---

## Question 1

What is the name of this executable?

### Notes

- Review the scheduled task created shortly after the `curl` command.
- The command creates a scheduled task named **Run Windows Defense System** that executes the following executable.

### Answer

`MsMpEng.exe`

---

## Question 2

What is the name of the Windows Application?

### Notes

- Search for `MsMpEng.exe` in the process logs.
- The executable belongs to the following Windows application.

### Answer

`Windows Defender`

---

## Question 3

What is the full path of the file on this system?

### Notes

- The scheduled task command specifies the executable path.

### Answer

`C:\Users\Public\Documents\MsMpEng.exe`

---

## Question 4

There's another file in the same folder on this system.

What is the name of that file?

### KQL Query

```kql
ProcessEvents
| where timestamp > datetime(2024-03-18T12:45:16.000Z)
| where hostname == "6BAN-DESKTOP"
| where process_commandline contains "C:\\Users\\Public\\Documents"
```

### Notes

- Review the second `curl` command.
- The attacker downloads a DLL into the same directory.

### Answer

`MpSvc.dll`

---

## Question 5

What is this attack called?

### Notes

- The attacker places a malicious DLL beside a legitimate executable to abuse Windows DLL loading behavior.

### Answer

`DLL hijacking`

---

## Question 6

How many processes is `MsMpEng.exe` creating on Eddie's system?

### KQL Query

```kql
ProcessEvents
| where hostname == "6BAN-DESKTOP"
| where parent_process_name contains "MsMpEng.exe"
```

### Answer

`0`

---

## Question 7

How many total processes did `MsMpEng.exe` create across the entire network?

### KQL Query

```kql
ProcessEvents
| where parent_process_name contains "MsMpEng.exe"
```

### Answer

`7`

---

## Question 8

Who's the username associated with these events?

### Notes

- Review the process events where `MsMpEng.exe` is the parent process.

### Answer

`dascully`

---

## Question 9

What's their role in the company?

### KQL Query

```kql
Employees
| where username == "dascully"
| project role
```

### Answer

`Director of Military Health Services`

---

## Question 10

What is the destination URL from the command run at timestamp `2024-04-02T12:12:44Z`?

### KQL Query

```kql
ProcessEvents
| where timestamp == datetime(2024-04-02T12:12:44Z)
```

### Notes

- Review the process command line at the specified timestamp.
- The second event contains the FTP destination URL.

### Answer

`ftp://algoadvertise.com/incoming/empirehealth_dump/`

---

## Question 11

Did Dana get the email just like Eddie did?

At what time?

### KQL Query

```kql
Email
| where recipient == "dana_scully@empirehealth.ny"
| where link contains "Veterans_Medical_Services.zip"
```

### Answer

`2024-03-18T11:45:34Z`

---

## Question 12

When did the first process run by `MsMpEng.exe` occur on Dana's machine?

### KQL Query

```kql
ProcessEvents
| where username == "dascully"
| where parent_process_name == "MsMpEng.exe"
```

### Answer

`2024-04-02T10:46:19Z`

---

## Question 13

When did the last process run by `MsMpEng.exe` occur?

### KQL Query

```kql
ProcessEvents
| where username == "dascully"
| where parent_process_name == "MsMpEng.exe"
| sort by timestamp desc
```

### Answer

`2024-04-02T13:32:44Z`

---

## Question 14

One command run by `MsMpEng` mentions patient records.

What is the network share path mentioned in this command?

### KQL Query

```kql
ProcessEvents
| where username == "dascully"
| where parent_process_name == "MsMpEng.exe"
| where process_commandline contains "patient"
```

### Notes

- Review the `-path` parameter in the command line.

### Answer

`\\recordssrv01\confidential\service_members\patient_records_2024\`

---

## Question 15

`MsMpEng` is connecting to `algoadvertise.com` and downloading what looks like a browser dumping tool.

What file path is this tool saved to?

### KQL Query

```kql
ProcessEvents
| where username == "dascully"
| where parent_process_name == "MsMpEng.exe"
```

### Notes

- Review the second process event.
- The browser dumping tool is saved using the `-OutFile` parameter.

### Answer

`C:\Users\Public\Documents\dmp.exe`

---

## Question 16

A few minutes after downloading the browser dumping tool, the attackers use it to target a specific site.

What is the domain targeted by the browser dumping tool?

### Notes

- Review the third process event.
- The target website appears in the `-target_site` argument.

### Answer

`ehr.empirehealth.ny`

---

## Question 17

What does EHR stand for here?

### Notes

- EHR is a common healthcare acronym.

### Answer

`Electronic Health Records`

---

## Question 18

Bingo. They're targeting the EHR system.

What is the file path where the attacker saved the browser dump to?

### Notes

- Review the third process event.
- The output location is specified using the `-output` parameter.

### Answer

`C:\Users\Public\Documents\browser_dump.txt`

---

## Question 19

A few moments later, the attacker exfiltrates data using the PowerShell command `Start-BitsTransfer`.

What URL does this command connect to?

### Notes

- Review the fifth process event.
- The destination is specified with the `-Destination` parameter.

### Answer

`ftp://algoadvertise.com/incoming/empirehealth_dump/`

---

## Question 20

Before leaving, the attacker clears the Windows event logs to hide what they've done.

What command do they use to do this?

### Notes

- Review the sixth process event.
- The attacker clears the Security, System, and Application event logs.

### Answer

```text
wevtutil cl Security && wevtutil cl System && wevtutil cl Application
```

---

## Question 21

Let's report this back to KCHQ.

Type `done`.

### Answer

`done`

---