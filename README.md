## Description

DirGrep is a Bash script designed to simplify and combine the process of directory fuzzing and keyword searching within a specified domain. It leverages Gobuster for directory fuzzing and curl for sending HTTP requests.

Can be useful in CTFs searching for keywords on a domain, or searching for statements that could represent a vulnerability on the domain you're scanning

## Features

- Directory fuzzing using Gobuster
- Keyword searching in the content of the discovered directories
- Customizable User-Agent and cookies for HTTP requests
- Retry mechanism for failed HTTP requests
- Logging of operations to a file

## Requirements

- Gobuster
- curl

## Usage
./dirgrep.sh [-u user_agent] [-d domain] [-c cookie] [-h | -help]
## Options
-u user_agent: Specify a custom User-Agent for curl requests (optional).

-d domain: Specify the domain to fuzz.

-c cookie: Specify a custom cookie to be used with curl requests (optional) (e.g -c NAME:VALUE).

-h, -help: Show the help message.

## Interactive Commands
While the tool is in use, the following commands are available:

EXIT: Exit the tool.
RESCAN: Rescan the domain using the same wordlist.
Notes
Press Ctrl+C to interrupt domain scanning and search with currently found directories.
Leave the URL field blank to proceed with the last scanned domain.
License
This project is licensed under the terms of the MIT license.
