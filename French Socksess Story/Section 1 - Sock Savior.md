# Section 1: Sock Savior

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

---

## Question 1

Type I've got this to start the mission.

### Answer

`I've got this`

---

## Question 2

How many emails does your query return?

### KQL Query

```kql
Email
| where subject == "Pay up or the world will know your lies"
```

### Answer

`3`

---

## Question 3

What email address did the threat actor use to send the extortion mail?

### KQL Query

```kql
Email
| where subject == "Pay up or the world will know your lies"
| distinct sender
```

### Answer

`theempireownsyou@proton.me`

---

## Question 4

What is the name of the highest ranking employee?

### KQL Query

```kql
Email
| where subject == "Pay up or the world will know your lies"
| distinct recipient
| lookup Employees on $left.recipient == $right.email_addr
```

### Notes

- Review the recipients of the extortion email.
- Join against the Employees table.
- Identify the highest-ranking employee among the recipients.

### Answer

`Cho Cetkipu`

---

## Question 5

What is the first command you see coming from that process?

### KQL Query

```kql
ProcessEvents
| where hostname in ("SCHR-MACHINE", "9RGD-MACHINE")
| where timestamp between (datetime(2024-08-30T00:00:00.000Z) .. datetime(2024-08-31T00:00:00.000Z))
```

### Notes

- Review processes where `cmd.exe` appears as the parent process.
- The first suspicious command maps a network share.

### Answer

`net use Z: \\Server\Contracts\Hidden`

---

## Question 6

To which folder was the data copied? (only paste the part after the username in the path)

### Notes

- Review the commands immediately after the network share access.
- The `xcopy` command stages files into a local directory.

### Answer

`\\Downloads\\notfrench`

---

## Question 7

What password are they using to protect the archive?

### Notes

- The archive creation command includes the password argument.

### Answer

`sn3@ky`

---

## Question 8

What is the name of that legitimate Windows tool?

### Notes

- The attacker uses a legitimate Windows utility to transfer files in the background.

### Answer

`bitsadmin`

---

## Question 9

What is the name of the domain to which the archived files were sent?

### Notes

- Review the `bitsadmin` transfer destination.

### Answer

`liarliarsocksonfire.net`

---

## Question 10

What is the username of that employee?

### KQL Query

```kql
ProcessEvents
| where hostname !in ("SCHR-MACHINE", "9RGD-MACHINE")
| where process_commandline contains "bitsadmin"
| distinct username
```

### Answer

`mioz`

---

## Question 11

What is the role of the employee?

### KQL Query

```kql
Employees
| where username == "mioz"
```

### Answer

`Customer Service Pinky Toe`

---

## Question 12

What is the name of the file that was archived, staged in the Downloads folder?

### KQL Query

```kql
ProcessEvents
| where username == "mioz"
| where process_commandline contains ".rar"
```

### Notes

- Review the first archive creation command.
- Identify the file being staged into the Downloads folder.

### Answer

`Customers.csv`

---

## Question 13

Which software does that process belong to?

### KQL Query

```kql
ProcessEvents
| where username == "mioz"
| where process_commandline contains "Customers.csv"
```

### Notes

- Review the process responsible for accessing the file.
- Identify the parent software associated with that process.

### Answer

`DbVisualizer`

---

## Question 14

What tool was used to dump credentials for the database and from LSASS memory?

### KQL Query

```kql
ProcessEvents
| where username == "mioz"
| where timestamp <= datetime(2024-08-18T21:34:16Z)
| order by timestamp desc
```

### Notes

- Review process activity leading up to the credential access.
- The executable appears near the top of the timeline.

### Answer

`LaZagne.exe`

---

## Question 15

What was this recon command?

### Notes

- Review the process command lines around the credential dumping activity.
- One command enumerates installed software.

### Answer

`wmic product get name`

---

## Question 16

What other tool was downloaded the same way?

### Notes

- Search for `invoke` activity in the process logs.
- Another archive is downloaded using the same technique.

### Answer

`dnscat2`

---

## Question 17

What domain was used to establish the C2 channel?

### Notes

- Search for `dnscat` activity.
- Review the associated communications.

### Answer

`thesockwhisperer.com`

---

## Question 18

What is the name of the Powershell script you found?

### KQL Query

```kql
FileCreationEvents
| where username == "mioz"
| where timestamp between (datetime(2024-08-18T16:10:29Z) .. datetime(2024-08-18T16:58:29Z))
```

### Answer

`talking_socks.ps1`

---

## Question 19

Did Mike Oz receive the file via email? (yes/no)

### KQL Query

```kql
Email
| where recipient == "mike_oz@jusdechaussette.fr"
| where link contains "holesinmysocks.jpeg"
```

### Answer

`no`

---

## Question 20

When was the file successfully uploaded via the contact form?

### KQL Query

```kql
InboundNetworkEvents
| where url contains "holesinmysocks.jpeg"
```

### Notes

- Review records containing the upload.
- Locate the event containing the word `success`.

### Answer

`2024-08-18T14:02:52Z`

---

## Question 21

What domain did the IP resolve to?

### KQL Query

```kql
PassiveDns
| where ip == "193.233.125.78"
| distinct domain
```

### Answer

`thesockwhisperer.com`

---

## Question 22

How many IP addresses are linked to the two domains?

### KQL Query

```kql
PassiveDns
| where domain in ("thesockwhisperer.com", "liarliarsocksonfire.net")
| distinct ip
```

### Answer

`3`

---

## Question 23

How many times did the threat actor browse to the company's website?

### KQL Query

```kql
let bad_ips = 
PassiveDns
| where domain in ("thesockwhisperer.com", "liarliarsocksonfire.net")
| distinct ip;
InboundNetworkEvents
| where src_ip in (bad_ips)
| count
```

### Answer

`25`

---

## Question 24

What search involving 'feet' did they make?

### KQL Query

```kql
let bad_ips = 
PassiveDns
| where domain in ("thesockwhisperer.com", "liarliarsocksonfire.net")
| distinct ip;
InboundNetworkEvents
| where src_ip in (bad_ips)
| where url contains "feet"
| project this_url = url_decode(url)
```

### Answer

`why are people posting their feet on this website`

---

## Question 25

What was the subject of the email sent from Mike's email address?

### KQL Query

```kql
Email
| where sender == "mike_oz@jusdechaussette.fr"
| where recipient in ("cho_cetkipu@jusdechaussette.fr", "brooke_entoe@jusdechaussette.fr")
```

### Answer

`Le President loves our latest design! Opportunity for presidential socks??? $$$$`

---

## Question 26

When was the link first clicked?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "http://thesockwhisperer.com/images/modules/public/decision.docx"
```

### Answer

`2024-08-19T14:51:05Z`

---

## Question 27

What new file is spawned right after the docx file is downloaded?

### KQL Query

```kql
FileCreationEvents
| where timestamp > datetime(2024-08-19T14:51:03Z)
| where hostname in ("SCHR-MACHINE", "9RGD-MACHINE")
```

### Notes

- Review file creation activity immediately after the document download.

### Answer

`talking_socks.ps1`

---

## Question 28

Type in time to debrief to finish the mission.

### Answer

`time to debrief`

---

## Question 29

Type in you're gonna go far to finish the module. Don't forget to celebrate successfully finishing your first module! You deserve it ;)

### Answer

`you're gonna go far`

---