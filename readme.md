# SSL Cipher Enum Tool

## Introduction
SSL Cipher Enum Tool is a PHP script designed to help in the enumeration of SSL ciphers for a given domain or IP address and port. Created by kaitoj, this tool provides a comprehensive overview of the security configurations of web servers, focusing on SSL/TLS protocols, cipher suites, DNS records, server headers, and the presence of security features like HTTP to HTTPS redirects and HSTS (HTTP Strict Transport Security).

## Features
- Enumerate SSL/TLS cipher suites.
- Retrieve DNS records for the given domain.
- Check for HTTP to HTTPS redirects.
- Test for HSTS (HTTP Strict Transport Security).
- Test SSL/TLS versions.
- Obtain server headers.

## Requirements
- PHP 8.0 or higher.
- Curl module for PHP.
- Permission to execute external commands from PHP if required.

## Installation
1. Clone the repository to your local machine or server:
```bash
git clone https://github.com/punkintech/ssl-cipher-enum-tool.git
```
2. Navigate to the script's directory:
```bash
cd ssl-cipher-enum-tool
```

## Usage
To use the SSL Cipher Enum Tool, execute the script from the command line with the domain or IP address and the port as arguments. Here is a basic example:
```bash
php sslCipherEnumTool.php

Enter the hostname or IP address of the server: example.com
Enter the port number of the server (press Enter for default - 443): 
```
or you can write the commands on a single line as below;
```bash
php sslCipherEnumTool.php [-h www.example.com] [-p 443] [-o path/to/file.txt]
```
-p = port
-h = hostname
-o = output file

If either the -h or -p parameters are missing you will be prompted to enter those details.
## Acknowledgments

@kaitoj, for developing the SSL Cipher Enum Tool.
Contributors and community members who have offered valuable insights and suggestions.

For support, feature requests, or contributions, please visit the GitHub repository.

Thank you for using the SSL Cipher Enum Tool.
