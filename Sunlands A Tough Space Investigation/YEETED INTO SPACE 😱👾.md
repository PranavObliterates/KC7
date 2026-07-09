# Section: YEETED INTO SPACE

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

What is the domain the attackers used to compromise SASA employees interested in the International Space Summit?

### KQL Query

```kql
Email
| where link contains "summit"
```

### Answer

`Intlspacesummit2123.info`

---

## Question 2

Which top-level domain (TLD) used by the attacker suggests evidence of foreign interference?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "Intlspacesummit2123.info"
| distinct url
| where url contains "redirect"
```

### Answer

`.lu`

---

## Question 3

What was the most common file (name) that victims downloaded from the attacker domains in Q2?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains ".lu"
| extend paths = tostring(parse_url(url).Path)
| extend files = tostring(parse_path(paths).Filename)
| summarize count() by files
```

### Answer

`AsteroidMiningBrief.ppt`

---

## Question 4

Right after the victims downloaded the files from Q3, the attackers ran a command to connect to their infrastructure.

What is the password?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "-pw"
| distinct process_commandline
```

### Notes

- Review the command line parameters containing `-pw`.

### Answer

`Aliens!:D`

---

## Question 5

The attackers ran commands to discover more about their victims’ network.

What is the hostname of the first victim with these commands? This includes compromised hosts that may have been impacted outside of the file in Q3.

### KQL Query

```kql
let compro_files = 
OutboundNetworkEvents
| where url contains ".lu"
| extend paths = tostring(parse_url(url).Path)
| extend files = tostring(parse_path(paths).Filename)
| summarize count() by files
| sort by count_ desc;

let compro_hosts =
FileCreationEvents
| where filename in (compro_files)
| distinct hostname;

ProcessEvents
| where hostname in (compro_hosts)
| where process_commandline contains "nbtstat"
```

### Answer

`OWQK-MACHINE`

---

## Question 6

When did the attackers first run a command to maintain their foothold in victim devices despite restarts, changed credentials, and other interruptions?

### KQL Query

```kql
ProcessEvents
| where process_commandline has_all ("plink", "schtasks")
```

### Answer

`2123-07-19T12:00:03Z`

---

## Question 7

We know that some of the Sunlands bigwigs got compromised by our threat actor, the question is how…find the role that was compromised most frequently with the command from question 6.

How many hosts linked to this role were compromised?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "schtasks /create /sc onstart /RU"
| lookup Employees on $left.hostname == $right.hostname
| summarize count() by role
```

### Answer

`175`

---

## Question 8

One of these compromised hosts was used as a vector to target an OP account with full control of the domain.

Which account was successfully compromised?

### KQL Query

```kql
let bad_host_ip = 
ProcessEvents
| where process_commandline contains "schtasks /create /sc onstart /RU"
| lookup Employees on $left.hostname == $right.hostname
| distinct ip_addr;

let usernames =
AuthenticationEvents
| where src_ip in (bad_host_ip)
| where username contains "domain"
| where result contains "success"
| distinct username;

ProcessEvents
| where username in (usernames)
```

### Answer

`jeburbage_domain_admin`

---

## Question 9

What account did the actor compromise in order to gain access to the account from Q8?

### KQL Query

```kql
AuthenticationEvents
| where username == "jeburbage_domain_admin"
| lookup Employees on $left.src_ip == $right.ip_addr
```

### Notes

- Review the associated usernames and identify the account used prior to compromising the domain administrator account.

### Answer

`dacusack`

---

## Question 10

What time did the attackers dump credentials?

### KQL Query

```kql
let bad_host_ip = 
ProcessEvents
| where process_commandline contains "schtasks /create /sc onstart /RU"
| lookup Employees on $left.hostname == $right.hostname
| distinct ip_addr;

let usernames =
AuthenticationEvents
| where src_ip in (bad_host_ip)
| where username contains "domain"
| where result contains "success"
| distinct username;

ProcessEvents
| where username in (usernames)
```

### Notes

- Review process command lines for credential dumping activity.

### Answer

`2123-07-19T13:43:24Z`

---

## Question 11

Now that the attacker has full access to the network, what file did they use to stage exfiltration data about the United Sunlands’ sensitive rocket tech and spaceport deal?

### KQL Query

```kql
FileCreationEvents
| where filename has_any (".7z", ".zip", ".rar")
```

### Notes

- Review archive files manually and identify the suspicious staging archive.

### Answer

`snlnds_s3cr3ts.rar`

---

## Question 12

The attackers transferred the exfiltrated data to what URL?

### KQL Query

```kql
ProcessEvents
| where username in ("wiitblend", "resunshine")
| where timestamp > datetime(2123-07-19)
```

### Notes

- Search for the encrypted PowerShell (`-enc`) command.
- Decode the Base64 payload.
- Decode the resulting decimal values.
- Decode the text output to identify the destination URL.

### CyberChef Recipe

```text
From Base64
→ From Decimal (Delimiter: Comma)
→ Decode Text (UTF-8)
```

**CyberChef Link**

https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)From_Decimal('Comma',false)Decode_text('UTF-8%20(65001)')

### Answer

`http://spaceresearch.as/exfil/`

---