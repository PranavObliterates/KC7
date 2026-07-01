# Section 1: SCADA NADA

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

---

## Question 1

BREAKING NEWS!: Massive Power Outage Disrupts One of the Country’s Premier Cybersecurity Conferences!

Enter Power Up to continue.

### Answer

Power Up

---

## Question 2

Before diving into the investigation, let's cover the basics.

Enter Grid Lock to continue.

### Answer

Grid Lock

---

## Question 3

Okay, Blue Teamer… the city of Chicago and its citizens need you to investigate this.

Enter Mission Accepted to continue.

### Answer

Mission Accepted

---

## Question 4

How many results are there for processes that contain SCADA in the commandline?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "SCADA"
```

### Answer

5

---

## Question 5

A command was run to scan the network and gather information about SCADA systems.

What is the name of the executable that was used to perform this scan?

### KQL Query

```kql
ProcessEvents
| where process_commandline has_all ("SCADA", ".exe")
| project process_commandline
```

### Answer

ICSScanner.exe

---

## Question 6

Paste the full timestamp for when this process was executed.

### Answer

2024-09-09T11:17:44Z

---

## Question 7

It looks like an external file was downloaded from a suspicious domain.

What command was used to download this file?

### KQL Query

```kql
ProcessEvents
| where process_commandline has_all ("SCADA", "curl")
```

### Answer

curl -o C:\ProgramData\SCADA_Malicious_Commands.txt

---

## Question 8

A destructive tool was used to wipe data and cause the SCADA systems to shut down.

What is the name of the executable that was used to do this?

### KQL Query

```kql
ProcessEvents
| where process_commandline has_all (".exe", "SCADA")
| where username contains "jisaetang"
```

### Notes

Read through the programs executed.

### Answer

KillDisk.exe

---

## Question 9

What legitimate Windows tool was exploited to carry out these remote executions?

### Answer

psexec

---

## Question 10

What executable did the threat actor use to establish persistence and perform reconnaissance on the SCADA systems during the attack?

### Answer

BlackEnergy.exe

---

## Question 11

According to threat intelligence reports, what is the name of the group responsible for these attacks?

### Answer

Sandworm

---

## Question 12

What is the timestamp for the first time BlackEnergy was observed running in the command line on any host in our environment?

### KQL Query

```kql
FileCreationEvents
| where filename == "BlackEnergy.exe"
```

### Answer

2024-08-29T08:28:45Z

---

## Question 13

On how many hosts was BlackEnergy present?

### KQL Query

```kql
FileCreationEvents
| where filename == "BlackEnergy.exe"
| summarize dcount(hostname)
```

### Answer

1

---

## Question 14

What is the hostname where BlackEnergy was found?

### KQL Query

```kql
FileCreationEvents
| where filename == "BlackEnergy.exe"
| project hostname
```

### Answer

BDC0-DESKTOP

---

## Question 15

What is the name of the employee that BDC0-DESKTOP belongs to?

### KQL Query

```kql
Employees
| where hostname == "BDC0-DESKTOP"
| project name
```

### Answer

Jibby Saetang

---

## Question 16

What is the employee's role?

### KQL Query

```kql
Employees
| where hostname == "BDC0-DESKTOP"
| project role
```

### Answer

SCADA Operator

---

## Question 17

What is the name of the file that the user downloaded, which is likely related to BlackEnergy?

### KQL Query

```kql
FileCreationEvents
| where hostname contains "BDC0-DESKTOP"
```

### Notes

Search around the timestamp 2024-08-29 and look for unusual filenames.

### Answer

Urgent_Cyber_Threat_Alert.zip

---

## Question 18

What is the timestamp for when the user downloaded that file?

### KQL Query

```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.8"
| where url has "Urgent_Cyber_Threat_Alert.zip"
| project timestamp
```

### Answer

2024-08-29T08:28:01Z

---

## Question 19

What is the SHA256 hash of the file created immediately after the downloaded file?

### KQL Query

```kql
FileCreationEvents
| where hostname == "BDC0-DESKTOP"
| where timestamp >= datetime(2024-08-29)
```

### Answer

1dc1dbfc1d636fed5cebe43787a7abf2df4fbb51e1beaec34ba72dd5152edc81

---

## Question 20

What process shows the user opening the zip file?

### KQL Query

```kql
ProcessEvents
| where hostname == "BDC0-DESKTOP"
| where process_commandline contains "alert.zip"
```

### Answer

Explorer.exe "C:\Users\jisaetang\Downloads\Urgent_Cyber_Threat_Alert.zip"

---

## Question 21

What is the name of the domain that BlackEnergy beacons to after execution?

### KQL Query

```kql
ProcessEvents
| where hostname == "BDC0-DESKTOP"
| where timestamp > datetime(2024-08-29)
| where process_commandline contains "c2"
```

### Answer

chicagogridupdates.com

---

## Question 22

To find out why, enter Unmask the Phish.

### Answer

Unmask the Phish
