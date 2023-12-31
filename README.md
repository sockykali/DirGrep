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
`./dirgrep.sh [-u user_agent] [-d domain] [-c cookie] [-h | -help]`

## Quickstart
```curl -sL https://raw.githubusercontent.com/sockykali/DirGrep/main/DirGrep.sh | tr -d '\r' > DirGrep.sh && chmod +x DirGrep.sh && ./DirGrep.sh```

To add as a tool on your system, run this (OffSec will include it in the Repo... soon... hopefully...)

```sudo cp DirGrep.sh /usr/local/bin/dirgrep```

You can then use `dirgrep -help`

## Options
-u user_agent: Specify a custom User-Agent for curl requests (optional).

-d domain: Specify the domain to fuzz.

-c cookie: Specify a custom cookie to be used with curl requests (optional) (e.g -c NAME:VALUE).

-h, -help: Show the help message.

## Interactive Commands
While the tool is in use, the following commands are available:

EXIT: Exit the tool.

RESCAN: Rescan the domain using the same wordlist.

## Notes
Press Ctrl+C to interrupt domain scanning and search with currently found directories.

Leave the URL field blank to proceed with the last scanned domain.

Script will dump a lot of messy log files to /tmp. To protect from information disclosure, chmod 600 is ran on these files.
If you want these log files for some reason, you can modify Constants on the script with your desired directory.

Saving results to a text file will always write to the working directory

## Contact

Feedback, improvements, issues, suggestions, banter, please reach me here - dirgrep@proton.me

## License
This project is licensed under the terms of the MIT license.
