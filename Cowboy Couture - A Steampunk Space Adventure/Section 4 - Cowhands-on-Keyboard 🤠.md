# Section 4: Cowhands-on-Keyboard 🤠

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

You thought you had it all figured out, but this new discovery has left you confused. What does this mean? You want to reach out to Wade for help, but you remember that he's about to give his closing keynote. Frustrated, you sift through your CISSP notes, but can't find anything there to help you think through this problem.

Then, you remember some of the questions you answered earlier in this training module and it suddenly hits you. You know just what to do!

Enter Anyone can do it! to continue.

### Answer

`Anyone can do it!`

---

## Question 2

Earlier in your investigation you learned about the count operator and how it can help you quickly uncover patterns of behavior.

With this in mind, you query the authentication logs to see how many times the suspicious 192.124.249.15 IP was used to successfully login.

How many succesful logins were made from that IP?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "192.124.249.15"
| where result contains "success"
| count
```

### Answer

`2`

---

## Question 3

You only observed one login into Megan’s account. Hmmm… 🤔 Who else’s account was accessed by this IP?

What is the username for the other employee that this IP was used to log into?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "192.124.249.15"
| where result contains "success"
```

### Answer

`jahartley`

---

## Question 4

You've discovered a second employee who is possibly compromised! Let's dig deeper into who this employee is.

What is this employee's role?

### KQL Query

```kql
Employees
| where username == "jahartley"
```

### Answer

`CEO`

---

## Question 5

Oh no!🤦‍♂️ It’s our new CEO!

This doesn’t look good, so you continue digging into the activity on their machine.

To keep the investigation focused, we can timebound our analysis. This means narrowing down the logs to events that happened after the suspicious login, helping us focus on relevant activity and reduce unnecessary noise.

Not long after the user behind the 192.124.249.15 IP accessed the CEO’s machine, there’s evidence of them establishing persistence.

Persistence usually involves placing a hidden program or a backdoor on the system, allowing the attacker to come back and access the system whenever they want, without being noticed.

Enter the timestamp for when the attacker established persisitence.

### KQL Query

```kql
ProcessEvents
| where hostname == "JHTJ-DESKTOP"
| where timestamp between (datetime(2024-09-19T06:25:59Z) .. datetime(2024-09-20T15:25:27Z))
```

### Notes

- Review process activity after the suspicious login.
- Look for persistence-related activity.
- The suspicious process can be identified from the `process_commandline` field.

### Answer

`9/20/2024, 4:39:09 AM`

---

## Question 6

This no longer looks like the actions of a disgruntled designer. Right now, your best indicator is the suspicious IP address. Let’s see if we can leverage some threat intelligence to help the investigation.

You can use the PassiveDns table to map the IP address to domains to gain greater insight into the attacker's infrastructure.

How many domains does the 192.124.249.15 IP resolve to?

### KQL Query

```kql
PassiveDns
| where ip == "192.124.249.15"
| distinct domain
```

### Answer

`2`

---

## Question 7

Attackers will often use multiple domains, IPs, and email addresses during an attack. Let’s continue to pivot within the PassiveDNS table to see if you can uncover any more IPs or domains connected to this attacker’s infrastructure.

What newly uncovered IP resolves to the secure-celestial.com domain?

### KQL Query

```kql
PassiveDns
| where domain in ("secure-celestial.com", "celestialcowboy-support.com")
```

### Answer

`142.250.191.78`

---

## Question 8

You keep finding more! Let's pivot one more time to see if you can continue to uncover any additional domains. Why not, right? Pivoting is fun!

What is the name of the next domain that you've uncovered?

### KQL Query

```kql
let bad_ips =
PassiveDns
| where domain in ("secure-celestial.com", "celestialcowboy-support.com")
| distinct ip;
PassiveDns
| where ip in (bad_ips)
| distinct domain
```

### Answer

`cccouture-hr-update.com`

---

## Question 9

You can now use these new indicators to pivot into the web browsing logs and check if there has been any traffic to the uncovered domains. This can potentially help us understand how Jane and Megan were initially compromised.

Is there any evidence of network traffic to any of those domains? (Yes/No)

### KQL Query

```kql
OutboundNetworkEvents
| where url has_any ("cccouture-hr-update.com", "secure-celestial.com", "celestialcowboy-support.com")
```

### Answer

`Yes`

---

## Question 10

It looks like our employees visited these attacker-controlled websites and entered their credentials! This is a clear violation of our company's Acceptable Use Policy, which emphasizes the importance of verifying URLs and avoiding suspicious links. Failing to follow these guidelines has opened the door to a serious compromise!

But hold your horses🐎—how did Jane and Megan get tricked into visiting these sites? Were they lured in like cattle to a rustler’s corral?

Another table that logs URL links is the Email table, which may give us clues about how these attacks started. Let’s check there to see if anything stands out.

What is the subject of the email sent to Megan Lucia?

### KQL Query

```kql
Email
| where link has_any ("cccouture-hr-update.com", "secure-celestial.com", "celestialcowboy-support.com")
| where recipient == "megan_lucia@celestialcowboycouture.com"
```

### Answer

`URGENT: From your CEO - Immediate Action Required: You are getting promoted Cowboy!!!!`

---

## Question 11

Most KC7 games are modeled after the TTPs of real-world threat actors that we've investigated as part of the MSTIC and GHOST teams. But for the 2024 Wild West Hackin' Fest, we thought we’d shake things up and let fate decide the attack! We drew random cards from the Backdoors & Breaches deck, and the rest, as they say, is history.

Now, it’s your turn to figure out which cards match up with what you’ve uncovered in the data. The clues are all there—can you piece it together?

Which Backdoors & Breaches initial compromise card was played here?

### Notes

- Visit the Backdoors & Breaches card reference:
  `https://bnb.silverday.de/about/cards.php`
- Review the Initial Access cards.
- The attack scenario aligns with a phishing email impersonating the CEO.

### Answer

`Phish`

---

## Question 12

In the end, your hard work paid off, and you successfully cleared Megan of any wrongdoing. The real culprit was identified, and Celestial Cowboy Couture’s reputation was restored. CEO Jane Hartley, recognizing her earlier mistake in overlooking Megan’s contributions, finally gave her that long-deserved promotion. With Megan leading the way, the team quickly pivoted and designed a new collection that made an international splash.

Now, every year in October, hundreds of well-dressed cult members fans descend upon the little town of Deadwood to celebrate the brand’s innovative designs and its unique contribution to the fashion world. Celestial Cowboy Couture not only recovered from the breach but also cemented its legacy as a forward-thinking, boundary-pushing brand in the global fashion scene.

Enter Happy Trails to complete this investigation.

### Answer

`Happy Trails`

---