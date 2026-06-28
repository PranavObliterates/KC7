# Section 3: World Domination Nation

## Table of Contents
- [Question 1](#question-1)
- [Question 2](#question-2)

---

## Question 1
Robert Russell reported seeing prompts for failed logins against his account, your manager wants you to investigate. What IP address does Robert usually use to login to his mail account?

### KQL Query
```kql
Employees
| where name == "Robert Russell"
```

### Answer
`10.10.4.55`

---

## Question 2
That IP appears to be a private (RFC1918) IP address, so we aren't too concerned about it yet. What is the most common public IP used by Robert Russell?

### KQL Query
```kql
AuthenticationEvents
| where hostname == "SSDW-LAPTOP"
```

### Answer
`48.147.171.98`

### Explanation
Since he might login into his host machine with his private ip sometimes we look into authenticationevents.

