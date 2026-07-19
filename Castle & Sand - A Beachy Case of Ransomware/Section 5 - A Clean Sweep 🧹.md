# Section 5: A Clean Sweep 🧹

## Table of Contents
- [Question 1](#question-1)
- [Question 2](#question-2)
- [Question 3](#question-3)
- [Question 4](#question-4)
- [Question 5](#question-5)
- [Question 6](#question-6)

---

## Question 1

Look up the IP addresses from Q8.

Which IP address is in the country that hosted the Winter Olympics a few years ago (South Korea)?

### Notes

- IPs from Section 4 Question 8:
  - `43.185.57.65`
  - `215.239.162.10`
  - `215.168.239.75`
  - `156.155.83.236`
  - `192.91.130.34`
  - `190.198.227.17`
  - `223.9.222.59`
  - `124.138.210.88`
  - `195.242.92.76`
- Manually perform IP geolocation lookups.
- The IP located in **South Korea** is:

### Answer

`124.138.210.88`

---

## Question 2

Which one hosted the Winter Olympics recently? If there's more than one, post any of them.

### Notes

- Perform geolocation lookups for the same IP addresses.
- China hosted the **2022 Winter Olympics**.
- One valid IP located in China is:

### Answer

`43.185.57.65`

---

## Question 3

Search the malicious files found in Q12 on VirusTotal.

Which file appears to not be malicious? Copy and paste the SHA256 hash.

### KQL Query

```kql
FileCreationEvents
| where filename in (
    "TSVIPSrv.dll",
    "1.exe",
    "i.exe",
    "wmi.dll",
    "procdump64.exe"
)
| distinct sha256
```

### Notes

- The query returns **7 unique SHA256 hashes**.
- Search each hash individually on VirusTotal.
- The following hash has **0 detections**.

### Answer

`e2a7a9a803c6a4d2d503bb78a73cd9951e901beb5fb450a2821eaf740fc48496`

---

## Question 4

Who signed the file?

### Notes

- Open the VirusTotal **Details** tab for the hash from Question 3.
- Defanged reference:

```text
hxxps://www[.]virustotal[.]com/gui/file/e2a7a9a803c6a4d2d503bb78a73cd9951e901beb5fb450a2821eaf740fc48496/details
```

### Answer

`Microsoft`

---

## Question 5

Research the malware files some more.

Which threat actor group may have used these in the past?

### Notes

- Search the malware hash on VirusTotal.
- Review the **Community** tab.
- Defanged reference:

```text
hxxps://www[.]virustotal[.]com/gui/file/490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994/community
```

- A community comment attributes previous use to:

### Answer

`APT41`

---

## Question 6

For what you found in Section 4, Q15, who developed this malware? Paste their username.

### Notes

- The malware identified in Section 4 Question 15 is **DNSExfiltrator**.
- OSINT investigation of the project's GitHub repository identifies the author.
- Defanged reference:

```text
hxxps://github[.]com/Arno0x/DNSExfiltrator/tree/master
```

### Answer

`Arno0x`

---