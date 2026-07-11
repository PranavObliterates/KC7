# Section 1: What's a Query? 🤔

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

---

## Question 1

Celestial Cowboy Couture, located in Deadwood, South Dakota, is on the verge of a huge breakthrough. The brand has gained increased exposure after world-famous male model John Strand starred in their latest advertising campaign. The campaign was a massive success, drawing global attention to the brand’s unique blend of cowboy and space fashion.

Unfortunately, this increased attention has also attracted cybercriminals eager to profit from the brand’s growth and popularity.

Your job is to uncover how these cybercriminals stole valuable information. By investigating the clues and analyzing the data, you can help to restore Celestial Cowboy Couture’s reputation.

Enter giddy up to get started.

### Answer

`giddy up`

---

## Question 2

What is the name of the Director of Happiness?

### KQL Query

```kql
Employees
| where role == "Director of Happiness"
| project name
```

### Answer

`Jason Blanchard`

---

## Question 3

What is Mary Ellen Kennel's role?

### KQL Query

```kql
Employees
| where name == "Mary Ellen Kennel"
| project role
```

### Answer

`Designer`

---

## Question 4

What is our model's exact role?

### KQL Query

```kql
Employees
| where role contains "model"
| project role
```

### Answer

`Underwear Model`

---

## Question 5

What is John Strand's IP Address?

### KQL Query

```kql
Employees
| where name == "John Strand"
| project ip_addr
```

### Answer

`10.10.0.3`

---

## Question 6

What is John Strand's hostname?

### KQL Query

```kql
Employees
| where name == "John Strand"
| project hostname
```

### Answer

`PFW2-DESKTOP`

---

## Question 7

What is John Strand's email address?

### KQL Query

```kql
Employees
| where name == "John Strand"
| project email_addr
```

### Answer

`john_strand@celestialcowboycouture.com`

---

## Question 8

How many emails did John Strand receive?

### KQL Query

```kql
Email
| where recipient == "john_strand@celestialcowboycouture.com"
| count
```

### Answer

`25`

---

## Question 9

How many distinct commands were run on John Strand's machine?

### KQL Query

```kql
ProcessEvents
| where hostname == "PFW2-DESKTOP"
| distinct process_commandline
| count
```

### Answer

`148`

---

## Question 10

Do a take 10 on any table and enter mosey on to continue.

### Answer

`mosey on`

---