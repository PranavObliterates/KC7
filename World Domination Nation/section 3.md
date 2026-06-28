# Section 3: GETTING SMARTER 🧠

## Table of Contents
- [Question 1](#question-1)
- [Question 2](#question-2)
- [Question 3](#question-3)
- [Question 4](#question-4)
- [Question 5](#question-5)
- [Question 6](#question-6)

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

---

## Question 3
You are unsure if this IP address is actually suspicious. What user agent did Robert show when logging in from that public IP? Just enter the last piece (e.g. Firefox/##.#)

### KQL Query
```kql
AuthenticationEvents
| where hostname == "SSDW-LAPTOP"
| where src_ip == "48.147.171.98"
```

### Answer
`Firefox/46.0`

---

## Question 4
We want to determine whether we should be concerned about that. Let's compare this user agent to the user's typical user agent. What is Robert Russell typical user agent (per the Employees table)? Just enter the last piece (e.g. Firefox/##.#)

### KQL Query
```kql
Employees
| where name == "Robert Russell"
| project user_agent
```

### Answer
`Firefox/46.0`

---

## Question 5
Ok that's probably just Russell logging in while working from home or something. What is the second most common user agent that we see being used to login to Russell's account? Just enter the last piece (e.g. Firefox/##.#)

### KQL Query
```kql
AuthenticationEvents
| where username == "rorussell"
| summarize count()by user_agent
```

### Answer
`Firefox/69.0`

---

## Question 6
How many different IPs were used in attempted logins to Russell's account via that second user agent?

### KQL Query
```kql
AuthenticationEvents
| where username == "rorussell"
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| distinct src_ip
| count 
```

### Answer
`20`

