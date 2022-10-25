# Windows-Security-Assessment
Windows security assessment PowerShell script - just run it and inspect the ZIP output.

Performs only non-intrusive passive checks, such as exporting Group Policies (GPResult), Audit Policies, Security Policies, Protocol Usage (SMB, NTLM, etc.), and general system inforamtion (installed software, running processes, hotfixes, etc.).

Preferably, should be run with elevated admin privileges, to allow access to all relevant configurations.

Supports all Windows versions with PowerShell (2003/XP and above).

**In use by Sygnia Consulting: https://www.sygnia.co/**
