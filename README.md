# agrippina
## Disclaimer
Agrippina is a tool for finding and theoretically exploiting log poisoning through Local File Inclusion.
It is for educational purposes only. 
If you break the law you will most likely go to jail. There is intentionally less than no stealth in this tool. 

## Log Poisoning Attack
The attack is centered around 2 pieces. Poisoning the log file, and exploiting a Local File Inclusion in a web site on
the server.

## Mitigation
Simple. Do not allow the Web server access to the logs. Store logs off-ste.Don't use web pages with Local File Inclusions
