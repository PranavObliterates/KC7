# Section 1: They call me CRIMSON 🐀

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

---

## Question 1

There was a lot of emails going around about regulation and compliance.

When is the first time a sender with either of these terms show up? (Ignore emails from trusted partner companies.)

### KQL Query

```kql
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
```

### Answer

`2023-10-10T09:01:05Z`

---

## Question 2

Investigate these email addresses.

How many sender email addresses are linked together by the same theme?

### KQL Query

```kql
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| distinct sender
```

### Answer

`4`

---

## Question 3

How many unique subject lines were sent by these email addresses?

### KQL Query

```kql
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| distinct subject
```

### Answer

`6`

---

## Question 4

Which of these subject lines was used to target the fewest number of users?

### KQL Query

```kql
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| summarize count() by subject
| sort by count_ asc
```

### Answer

`[EXTERNAL] IMPORTANT: Provide your information now.`

---

## Question 5

Let's take all of the email addresses and look for how many distinct URLs were sent by them.

How many unique URLs were sent?

### KQL Query

```kql
let bad_senders =
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| distinct sender;

Email
| where sender in (bad_senders)
| distinct link
```

### Answer

`8`

---

## Question 6

How many employees clicked on these links?

### KQL Query

```kql
let bad_senders =
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| distinct sender;

let bad_links =
Email
| where sender in (bad_senders)
| distinct link;

OutboundNetworkEvents
| where url in (bad_links)
| distinct src_ip
```

### Answer

`20`

---

## Question 7

How many distinct employee roles clicked these links?

### KQL Query

```kql
let bad_senders =
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| distinct sender;

let bad_links =
Email
| where sender in (bad_senders)
| distinct link;

OutboundNetworkEvents
| where url in (bad_links)
| lookup Employees on $left.src_ip == $right.ip_addr
| distinct role
```

### Answer

`8`

---

## Question 8

How many Dark Magic Regulation Experts clicked the links?

### KQL Query

```kql
let bad_senders =
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| distinct sender;

let bad_links =
Email
| where sender in (bad_senders)
| distinct link;

OutboundNetworkEvents
| where url in (bad_links)
| lookup Employees on $left.src_ip == $right.ip_addr
| summarize count() by role
```

### Answer

`4`

---

## Question 9

What time did the first employee click on one of the links?

### KQL Query

```kql
let bad_senders =
Email
| where sender contains "regulation" or sender contains "compliance"
| where sender !endswith "researchcompliance.biz"
| distinct sender;

let bad_links =
Email
| where sender in (bad_senders)
| distinct link;

OutboundNetworkEvents
| where url in (bad_links)
| lookup Employees on $left.src_ip == $right.ip_addr
```

### Answer

`2023-10-16T07:48:29Z`

---

## Question 10

What is that employee's username?

### Notes

- Review the results from the previous query.
- The employee who first clicked the malicious link is identified in the joined `Employees` table.

### Answer

`sugupta`

---

## Question 11

Let's look at this employee's Authentication activity.

What is the most common user agent used by this employee? (Format `Firefox/XX.X`)

### KQL Query

```kql
AuthenticationEvents
| where username == "sugupta"
| summarize count() by user_agent
```

### Notes

- Return only the Firefox version from the full user-agent string.

### Answer

`Firefox/47.0;47.0`

---

## Question 12

When was there a login attempt from a different user agent for this employee?

### KQL Query

```kql
AuthenticationEvents
| where username == "sugupta"
| where user_agent == "Mozilla/5.0 (Macintosh; PPC Mac OS X 10_11_6; rv:1.9.2.20) Gecko/2011-05-02 06:39:07 Firefox/11.0"
```

### Answer

`2023-10-17T01:17:35Z`

---

## Question 13

From what IP address did this authentication occur?

### Notes

- Use the results from the previous query.

### Answer

`173.188.151.49`

---

## Question 14

How many login attempts were seen from this IP?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "173.188.151.49"
```

### Answer

`3`

---

## Question 15

Which user account was successfully logged in to from this IP?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "173.188.151.49"
| where result contains "success"
| project username
```

### Answer

`almcwaters`

---

## Question 16

Let's look back at all AuthenticationEvents.

Which user agent was used the most? (Format `Firefox/XX.X`)

### KQL Query

```kql
AuthenticationEvents
| summarize count() by user_agent
| sort by count_ desc
```

### Notes

- Return only the Firefox version from the full user-agent string.

### Answer

`Firefox/69.0;69.0`

---

## Question 17

How many user accounts had login attempts from this user agent?

### KQL Query

```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| distinct username
| count
```

### Answer

`405`

---

## Question 18

How many IP addresses were used with this user agent?

### KQL Query

```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| distinct src_ip
```

### Answer

`2635`

---

## Question 19

How many user accounts were successfully logged into using this user agent?

### KQL Query

```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| where result contains "success"
| distinct username
```

### Answer

`28`

---

## Question 20

This type of attack is known as a __.

### Notes

- Review the training guide.
- Numerous authentication attempts using a common user agent across many accounts are characteristic of a password spraying attack.

### Answer

`password spray`

---

## Question 21

Let's look for follow-on activity, including phishing emails targeting higher privileged and sensitive users.

What is the email subject that the threat actor used?

### KQL Query

```kql
let compro_mails =
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| where result contains "success"
| lookup Employees on $left.username == $right.username
| distinct email_addr;

Email
| where sender has_any (compro_mails) or recipient has_any (compro_mails)
| where sender contains "@deathcon-scholomance.io"
| summarize count() by subject
| sort by count_ desc
```

### Answer

`URGENT: Please provide locations where your research is located.`

---

## Question 22

The threat actor may have done some additional recon within the environment.

Checking the internal network events, what document did they look within the enclave's secretive shares?

### KQL Query

```kql
InboundNetworkEvents
| where url has_any ("secret", "enclave")
```

### Notes

- Search the returned events for document extensions such as `.pdf`, `.docx`, or `.rtf`.

### Answer

`important_research.docx`

---

## Question 23

The threat actor may have forgot how to do some reconnaissance in an internal environment.

What website did they use to get a refresher? Copy and paste the full URL.

### KQL Query

```kql
OutboundNetworkEvents
| where url has "recon"
| distinct url
```

### Answer

`https://svch0st.medium.com/active-directory-recon-cheat-sheet-76ccc16dc6e8`

---

## Question 24

Continue to investigate the threat actor.

They may have downloaded and used an archiving tool.

What URL did they use to download it?

### KQL Query

```kql
OutboundNetworkEvents
| where url has_any ("7-zip", "winrar")
```

### Answer

`https://www.7-zip.org/a/7z2002-x64.exe`

---

## Question 25

It looks like they staged some files for extraction.

What is the timestamp of the last file they archived and created?

### KQL Query (Identify Archived Files)

```kql
FileCreationEvents
| where filename contains ".7z"
| summarize count() by filename
| sort by count_ desc
```

### Notes

- Search the `FileCreationEvents` table for `.7z` archives.
- Two archive files are observed:
  - `documents.7z`
  - `research.7z`

### KQL Query (Find Final Archive Creation)

```kql
FileCreationEvents
| where filename has_any ("research.7z", "documents.7z")
| sort by timestamp desc
```

### Answer

`2023-11-03T10:24:43Z`

---