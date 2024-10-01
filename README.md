# IP Range Extractor for MikroTik and JSON Outputs

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Running with Python](#running-with-python)
  - [Running with Docker](#running-with-docker)
- [Output](#output)
- [Logging](#logging)
- [File Structure](#file-structure)
- [Contributing](#contributing)
- [License](#license)

## Introduction

The **IP Range Extractor** is a Python-based tool designed to download, parse, and extract IP address ranges from RIPE's `alloclist.txt` file for a specified country. It generates MikroTik `.rsc` configuration files suitable for firewall address lists and a corresponding JSON file for further processing or integrations.

## Features

- **Single `.rsc` File:** Generates a unified MikroTik `.rsc` file containing both IPv4 and IPv6 address lists under their respective sections.
- **JSON Output:** Produces a JSON file with all extracted IP entries, including details like allocation date and organization.
- **Command-Line Interface:** Accepts country codes as named arguments (e.g., `--country=ir`).
- **Docker Support:** Provides a `Dockerfile` for containerizing the application, ensuring consistent environments.
- **Comprehensive Logging:** Maintains detailed logs of the extraction and file generation processes for debugging and auditing.

## Prerequisites

- **Python 3.6+**
- **pip**
- **Docker** (optional, for containerization)

## Installation

### Clone the Repository

```bash
git clone https://github.com/vaheed/ip_country_extraction.git
cd ip_country_extraction
```

### Build the Docker

```bash
docker build -t ip_country_extraction .
```

### Run the Docker

```bash
docker run --rm -v $(pwd)/output:/app/output ip_country_extraction --country=ir
```
