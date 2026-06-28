# Section 3: World Domination Nation

## Question 1
Robert Russell reported seeing prompts for failed logins against his account, your manager wants you to investigate. What IP address does Robert usually use to login to his mail account?

### KQL Query
```kql
Employees
| where name == "Robert Russell"
```

### Answer
`10.10.4.55`

