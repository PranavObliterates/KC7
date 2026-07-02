# Section 2: Quarantine Quandary

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

We received a security alert a few days ago that a file with the word 'healthcare' was quarantined. We know that it's your first day here, but we get these alerts all the time and they are usually nothing. What could possibly go wrong?

What is the name of the file that was quarantined?

### KQL Query

```kql
SecurityAlerts
| where description contains "healthcare"
```

### Answer

`New_Healthcare_Protocols.docm`

---

## Question 2

Nice! You found the file! Now let's gather enough evidence for us to resolve this stupid alert and go chitchat at the water cooler.

What is the hostname of the computer that contained this file?

### Notes

- Check the alert description.

### Answer

`ZQHM-LAPTOP`

---

## Question 3

Ok, we have the machine name, let's figure out who it belongs to.

What is the name of the employee that this computer belongs to?

### KQL Query

```kql
Employees
| where hostname == "ZQHM-LAPTOP"
| project name
```

### Answer

`Jerry Jones`

---

## Question 4

Is this someone that should be reading a file like that?

What is that employee's role at Azure Crest Hospital?

### KQL Query

```kql
Employees
| where name == "Jerry Jones"
| project role
```

### Answer

`Resident Doctors`

---

## Question 5

It's looking like it's nothing just like they said. A doctor was just trying to download a file related to healthcare protocols.

When was this file created on the doctor's computer? (paste the full timestamp)

### KQL Query

```kql
FileCreationEvents
| where filename == "New_Healthcare_Protocols.docm"
| where hostname == "ZQHM-LAPTOP"
| project timestamp
```

### Answer

`2024-03-14T10:38:36Z`

---

## Question 6

Just to be sure, let's find out where this file came from.

What process did we see create this file? (process name)

### KQL Query

```kql
FileCreationEvents
| where filename == "New_Healthcare_Protocols.docm"
| where hostname == "ZQHM-LAPTOP"
| project process_name
```

### Answer

`chrome.exe`

---

## Question 7

That means the file was downloaded from the internet!

What domain was the file downloaded from?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "New_Healthcare_Protocols"
| where src_ip == "10.10.0.174"   //jerry's ip
```

### Answer

`takeyatimecarepartners.com`

---

## Question 8

Sneaky! Sneaky! That sounds a lot like a legitimate partner domain.

Which legitimate Azure Crest partner's domain is the threat actor attempting to mimic?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "carepartners"
```

### Notes

- Search using portions of the malicious domain to identify the legitimate partner domain it resembles.

### Answer

`emergencycarepartners.com`

---

## Question 9

Ok the file came from a shady looking domain, but why the heck did the user download it? It's possible they downloaded the file via a link in an email.

Let's try to find that email.

What is Jerry's email address?

### KQL Query

```kql
Employees
| where name == "Jerry Jones"
| project email_addr
```

### Answer

`jerry_jones@azurecresthospital.med`

---

## Question 10

How many emails did Jerry Jones receive?

### KQL Query

```kql
Email
| where recipient == "jerry_jones@azurecresthospital.med"
| count
```

### Answer

`23`

---

## Question 11

Let's drill down!

When did Jerry receive the email that contained a link to the quarantined file? (paste the full timestamp)

### KQL Query

```kql
Email
| where recipient == "jerry_jones@azurecresthospital.med"
| where link contains "New_Healthcare_Protocols"
```

### Answer

`2024-03-14T10:27:39Z`

---

## Question 12

Is this email legit?

What is the sender's address for that email?

### Answer

`medstaffinfo@hospitalcomm.org`

---

## Question 13

The 'reply to' address is different so you take note of that.

What 'reply to' address is used?

### Answer

`healthupdate@gmail.com`

---

## Question 14

What is the subject of the email?

### Answer

`[EXTERNAL] FW: 🚑 Attention Required: Urgent Pediatric Health Procedure Update 🌈;FW: 🚑 Attention Required: Urgent Pediatric Health Procedure Update 🌈;🚑 Attention Required: Urgent Pediatric Health Procedure Update`

---

## Question 15

It looks like Jerry received another email from this sender.

When did Jerry receive that email? (paste the full timestamp)

### KQL Query

```kql
Email
| where sender == "healthupdate@gmail.com"
| where recipient == "jerry_jones@azurecresthospital.med"
```

### Answer

`2024-03-06T11:49:48Z`

---

## Question 16

What filename seen in the link?

### Answer

`Pediatric_Care_Update.docm`

---

## Question 17

The following news just dropped about the happenings at Azure Crest. Apparently, the doctors are having trouble accessing any database systems, and have leaked these frustrations to the press. You've been so deep in your investigation that you didn't notice.

The IT director bursts into your office demanding answers. The C-suite is asking him how this could possibly have happened.

Type RIP to receive credit.

### Answer

`RIP`

---
