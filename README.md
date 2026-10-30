cat > README.md <<'EOF'
# Phishing Email Analysis (SOC Level 1 Project)

I analyzed 3 real phishing emails from the public Phishing Pot dataset. For each one I checked the headers, the sender, the links, the attachments, and the reputation of domains, IPs and files. Then I wrote a verdict, IOCs, MITRE ATT&CK techniques and recommended actions.

## My method

1. **Headers**: compare `From`, `Return-Path` and `Received`. Read SPF, DKIM and DMARC.
2. **Sender and domain**: fake brands, domain age (whois, crt.sh), IP owner.
3. **Body**: urgency, threats, rewards, hidden characters.
4. **Links**: extract all URLs, compare visible text with the real link.
5. **Attachments**: calculate the hash and search it on VirusTotal. Files are never opened.
6. **IOCs**: list all indicators, defanged.
7. **Verdict**: true positive or false positive, confidence, actions, limits.

## Cases

| # | Case | Type | Verdict | Key lesson |
|---|---|---|---|---|
| 01 | [Fake Bradesco / Livelo](reports/01-fake-bradesco-livelo.md) | Link phishing | Malicious | Sent from a rented VPS as root. Reputation tools gave false negatives |
| 02 | [Fake Amazon Prime](reports/02-fake-amazon-prime-payment.md) | Link phishing | Malicious | SPF, DKIM and DMARC all passed, but the email is still malicious |
| 03 | [Fake wire transfer + ISO](reports/03-iso-malware-wire-transfer.md) | Malware attachment | Malicious | ISO with a packed executable, 61/72 detections on VirusTotal |

## Tools

VirusTotal, urlscan.io, AbuseIPDB, crt.sh, whois, dig, Python (`email` module), WSL (Ubuntu).

## Sample source

All emails come from the public dataset [Phishing Pot](https://github.com/rf-peixoto/phishing_pot), in the `email/` folder:

| Case | Original file |
|---|---|
| 01 | `sample-1.eml` |
| 02 | `sample-10838.eml` |
| 03 | `sample-2571.eml` |

## Skills I practiced

- **Reading email headers**: comparing `From`, `Return-Path` and `Received` to find the real sender, and understanding SPF, DKIM and DMARC results (`pass`, `fail`, `temperror`, `none`).
- **Not trusting one tool**: I learned that a score of 0 on VirusTotal or AbuseIPDB does not mean "safe". Domains die and IPs are reused, so I cross-checked with headers, content and certificate history.
- **Spotting evasion tricks**: base64-encoded bodies, invisible Unicode characters, decoy attachments, ISO files used to hide an executable.
- **Safe analysis**: I read emails and attachments in memory and calculated hashes without ever opening a file.
- **Investigating infrastructure**: whois, DNS, crt.sh, urlscan.io and AbuseIPDB to build a timeline of a domain or an IP.
- **Writing a SOC report**: verdict, true/false positive classification, defanged IOCs, MITRE ATT&CK mapping, recommended actions, and the limits of my analysis.
- **Correcting myself on evidence**: I fixed my own conclusions when new data contradicted them (for example the real age of a domain).

## Privacy

I hid the information I judged necessary to protect, such as the names of real people, in the screenshots and reports. IOCs in the text are defanged (`hxxps`, `[.]`).