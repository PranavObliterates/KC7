# Section 1: KQL 101 🧰

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

Type done here when finished to earn your first 10 points!

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

`1500`

---

## Question 3

Which employee has the IP address: 10.10.2.1?

### KQL Query

```kql
Employees
| where ip_addr == "10.10.2.1"
```

### Answer

`Preston Lane`

---

## Question 4

How many emails did Jacqueline Henderson receive?

Note: You will need to look at the Employees table first to find Jacqueline's email address.

### KQL Query

```kql
let jac_email = 
Employees
| where name == "Jacqueline Henderson"
| distinct email_addr;
Email
| where recipient in (jac_email)
| count
```

### Answer

`26`

---

## Question 5

How many distinct senders were seen in the email logs from sunandsandtrading.com?

### KQL Query

```kql
Email
| where sender contains "sunandsandtrading.com"
| distinct sender
| count
```

### Answer

`2146`

---

## Question 6

How many unique websites did “Cristin Genao” visit?

### KQL Query

```kql
let cris_ip = 
Employees
| where name == "Cristin Genao"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (cris_ip)
| distinct url
```

### Answer

`45`

---

## Question 7

How many distinct domains in the PassiveDns records contain the word “shark”?

### KQL Query

```kql
PassiveDns
| where domain contains "shark"
| distinct domain
```

### Answer

`13`

---

## Question 8

What IPs did the domain “sharkfin.com” resolve to (enter any one of them)?

### KQL Query

```kql
PassiveDns
| where domain == "sharkfin.com"
```

### Notes

- Any IP returned by the query is a valid answer.

### Answer

`157.242.169.232`

---

## Question 9

How many unique URLs were browsed by employees named “Karen”?

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

`151`

---