# SQL-Injection-Scanner


## Introduction
SQL Injection is one of the most dangerous vulnerabilities in web applications. This scanner attempts to find such vulnerabilities by injecting malicious SQL payloads into parameters and analyzing the responses.
The goal of this tool is to provide an **automated, lightweight, and easy-to-use solution** to detect potential SQL injection flaws early in development or during security assessments.

## Features
- Detects both GET and POST-based SQL injection vulnerabilities
- Uses time-based, error-based, and boolean-based payloads
- Supports custom payload lists
- Proxy support (for Burp Suite, etc.)
- Generates a detailed vulnerability report
- Configurable timeout and delay
- Does not use external databases or third-party APIs

## How It Works
1. The scanner takes a target URL or POST data and identifies injectable parameters.
2. It injects various SQL payloads to test how the server responds.
3. It analyzes the HTTP response for signs of a successful SQL injection:
   - SQL error messages
   - Differences in response content or length
   - Delays (for time-based injections)
4. If a vulnerability is found, the tool reports the type, parameter, and payload used.
