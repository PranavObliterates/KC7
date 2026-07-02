# Azure Crest Hospital

## Section 1: KQL 101

### Question 1

Welcome to Azure Crest Hospital!

Enter ready to get started!

### Answer

ready

---

### Question 2

Run a take 10 on each table to understand the available data.

Type "done" to earn credit for this question.

### Answer

done

---

### Question 3

How many employees work at Azure Crest Hospital?

### Query

```kql
Employees
| count
```

### Answer

250

---

### Question 4

What is the Chief Financial Officer's name?

### Query

```kql
Employees
| where role == "Chief Financial Officer"
```

### Answer

Penny Pincher

---

### Question 5

How many emails did Penny Pincher receive?

### Query

```kql
Email
| where recipient == "penny_pincher@azurecresthospital.med"
| count
```

### Answer

30

---

### Question 6

How many distinct senders were seen in the email logs from pharmabest.net?

### Query

```kql
Email
| where sender has "pharmabest.net"
| distinct sender
| count
```

### Answer

236

---

### Question 7

How many distinct websites did Penny Pincher visit?

### Query

```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.1"
| distinct url
| count
```

### Answer

68

---

### Question 8

How many distinct domains in the PassiveDns records contain the word "health"?

### Query

```kql
PassiveDns
| where domain contains "health"
| distinct domain
| count
```

### Answer

28

---

### Question 9

What IPs did the domain "bit.ly" resolve to?

### Query

```kql
PassiveDns
| where domain contains "bit.ly"
```

### Answer

134.177.143.174

### Notes

42.143.126.108 was also accepted.

---

### Question 10

How many distinct URLs did employees with the first name "Mary" visit?

### Query

```kql
let mary_ips =
Employees
| where name has "Mary"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (mary_ips)
| distinct url
```

### Answer

119

---

### Question 11

How many authentication attempts did we see to the accounts of employees with the first name Mary?

### Query

```kql
let mary_name_accs =
Employees
| where name has "Mary"
| distinct username;

AuthenticationEvents
| where username in (mary_name_accs)
| count
```

### Answer

180

---

### Question 12

Congratulations! You''ve passed KQL 101!

Enter "ready" to earn credit for this question.

### Answer

ready
