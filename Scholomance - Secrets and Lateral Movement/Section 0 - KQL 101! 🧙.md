# Section 0: KQL 101! 🧙

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

---

## Question 1

Do a `take 10` on all the other tables to see what kind of data they contain.

Answer with `done` when you are ready to move on!

### Answer

`done`

---

## Question 2

How many employees are in the company?

### KQL Query

```kql
Employees
| count
```

### Answer

`888`

---

## Question 3

Each employee at Scholomance Hidden Enclave - DC2 is assigned an IP address.

Which employee has the IP address `10.10.0.20`?

### KQL Query

```kql
Employees
| where ip_addr == "10.10.0.20"
```

### Answer

`Rose Boyd`

---

## Question 4

How many emails did Elsie Hall receive?

### KQL Query

```kql
Email
| where recipient == "elsie_hall@deathcon-scholomance.io"
```

### Answer

`44`

---

## Question 5

How many distinct senders were seen in the email logs that contain links with `scholomance-suppliers.online`?

### KQL Query

```kql
Email
| where link contains "scholomance-suppliers.online"
| distinct sender
```

### Answer

`403`

---

## Question 6

How many unique URLs did **Becky Thrower** visit?

### KQL Query

```kql
let becky_ip =
Employees
| where name == "Becky Thrower"
| project ip_addr;

OutboundNetworkEvents
| where src_ip in (becky_ip)
| distinct url
```

### Answer

`80`

---

## Question 7

How many unique domains in the `PassiveDns` records contain the word **"documents"**?

### KQL Query

```kql
PassiveDns
| where domain contains "documents"
| distinct domain
```

### Answer

`4`

---

## Question 8

What IPs did the domain `information-documents.org` resolve to?

### KQL Query

```kql
PassiveDns
| where domain == "information-documents.org"
```

### Answer

`187.4.28.70`

---

## Question 9

How many unique URLs were browsed by employees named **Karen**?

### KQL Query

```kql
let karen_ips =
Employees
| where name has "Karen"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (karen_ips)
| distinct url
```

### Answer

`204`

---