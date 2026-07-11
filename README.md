# Vulnerable-Login

A deliberately vulnerable login form designed for security education and training. This application contains 12 common login authentication vulnerabilities for students to discover, exploit, and learn from.

## Disclaimer

**THIS APPLICATION IS FOR EDUCATIONAL PURPOSES ONLY!**

This code contains intentional security vulnerabilities. Never use this code in production environments or on any system that handles real user data. The authors are not responsible for any misuse or damage caused by this application.

## Purpose

This project is designed to help:
- Security students understand common web vulnerabilities
- Developers learn secure coding practices
- Penetration testers practice exploitation techniques
- Educators demonstrate real-world security flaws

## Live Demo

The application is hosted on GitHub Pages:
[https://yogsec.github.io/Vulnerable-Login](https://yogsec.github.io/Vulnerable-Login)

## Vulnerabilities Included

**VULN-001 - SQL Injection**
- Severity: Critical
- Description: User input is directly added to SQL queries, allowing attackers to bypass authentication

**VULN-002 - Plaintext Password Storage**
- Severity: Critical
- Description: Passwords are stored as plain text in localStorage without encryption

**VULN-003 - No Rate Limiting**
- Severity: Critical
- Description: Unlimited login attempts are allowed without any restrictions

**VULN-004 - No Account Lockout**
- Severity: High
- Description: Accounts are never locked even after multiple failed login attempts

**VULN-005 - Weak Passwords**
- Severity: High
- Description: Users are created with common and easily guessable passwords

**VULN-006 - Weak MD5 Hashing**
- Severity: High
- Description: Passwords are hashed using MD5 algorithm without salt

**VULN-007 - Verbose Error Messages**
- Severity: Medium
- Description: Error messages reveal whether a username exists in the system

**VULN-008 - User Enumeration**
- Severity: Medium
- Description: Attackers can determine which usernames are valid in the system

**VULN-009 - Session Fixation**
- Severity: High
- Description: Session ID is not regenerated after successful login

**VULN-010 - Hardcoded Credentials**
- Severity: Critical
- Description: Backdoor credentials are hardcoded in the application code

**VULN-011 - No HTTPS**
- Severity: Medium
- Description: Credentials are transmitted over unencrypted HTTP connection

**VULN-012 - CSRF Vulnerability**
- Severity: Medium
- Description: Anti-CSRF token is present but never validated


