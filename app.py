#!/usr/bin/env python3
"""
IP Range Extractor for MikroTik .rsc and JSON Files

This script downloads the RIPE `alloclist.txt` file, parses it to extract IP ranges
for a specified country code, and generates both MikroTik `.rsc` configuration files
and a JSON file containing the extracted data.

Usage:
    python app.py --country=ir

Requirements:
    - Python 3.6+
    - requests library

Author:
    Your Name
"""

import requests
import logging
import re
import sys
import argparse
from pathlib import Path
import ipaddress
import json

def setup_logging(log_file: Path):
    """
    Configures the logging settings.

    Args:
        log_file (Path): The path to the log file.
    """
    logging.basicConfig(
        filename=log_file,
        filemode='w',
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

def download_alloclist(url: str) -> list:
    """
    Downloads the alloclist.txt file from the specified URL.

    Args:
        url (str): The URL to download the alloclist.txt from.

    Returns:
        list: A list of lines from the downloaded file.

    Exits:
        If the download fails.
    """
    try:
        logging.info(f"Starting download of alloclist from {url}")
        response = requests.get(url)
        response.raise_for_status()
        logging.info("Download successful")
        return response.text.splitlines()
    except requests.RequestException as e:
        logging.error(f"Failed to download alloclist: {e}")
        sys.exit(1)

def parse_alloclist(lines: list, country_code: str) -> tuple:
    """
    Parses the alloclist lines to extract IP entries for the specified country code.

    Args:
        lines (list): The lines from alloclist.txt.
        country_code (str): The two-letter country code to filter by.

    Returns:
        tuple: Two lists containing IPv4 and IPv6 entries respectively.
    """
    logging.info(f"Starting to parse alloclist for country code: {country_code}")
    ip_entries_ipv4 = []
    ip_entries_ipv6 = []
    current_country = None
    section_name = None
    organization = None
    capture_ips = False

    # Regex patterns
    section_header_pattern = re.compile(r'^([a-z]{2})\.(\S+)', re.IGNORECASE)
    # Make 'ALLOCATED PA' optional and allow any trailing content
    ip_entry_pattern = re.compile(r'^(\d{8})\s+([\da-fA-F\.:/]+)(?:\s+ALLOCATED\s+PA)?$', re.IGNORECASE)

    for idx, line in enumerate(lines):
        original_line = line  # Keep the original line for accurate logging
        line = line.strip()
        logging.debug(f"Processing line {idx + 1}: {line}")

        # Check for section header (e.g., "ir.aasaam")
        header_match = section_header_pattern.match(line)
        if header_match:
            current_country = header_match.group(1).lower()
            section_name = header_match.group(2)
            logging.debug(f"Found section: {current_country}.{section_name}")
            if current_country == country_code:
                logging.info(f"Entering target section: {current_country}.{section_name}")
                capture_ips = False  # Reset capture flag
                organization = None
            else:
                capture_ips = False  # Not the target country
            continue

        if current_country == country_code:
            if not organization:
                if line:  # Assuming organization name is non-empty
                    organization = line
                    logging.debug(f"Found organization: {organization}")
                    continue
            else:
                if not line:
                    logging.debug("Blank line encountered after organization name, ready to capture IPs")
                    capture_ips = True
                    continue
                if capture_ips:
                    ip_match = ip_entry_pattern.match(line)
                    if ip_match:
                        date = ip_match.group(1)
                        ip_range = ip_match.group(2)
                        logging.debug(f"Extracted IP entry - Date: {date}, IP Range: {ip_range}")

                        # Determine if the IP is IPv4 or IPv6
                        try:
                            network = ipaddress.ip_network(ip_range, strict=False)
                            entry = {
                                'date': date,
                                'ip': ip_range,
                                'organization': section_name
                            }
                            if isinstance(network, ipaddress.IPv4Network):
                                ip_entries_ipv4.append(entry)
                            elif isinstance(network, ipaddress.IPv6Network):
                                ip_entries_ipv6.append(entry)
                        except ValueError as ve:
                            logging.warning(f"Invalid IP range '{ip_range}' on line {idx + 1}: {ve}")
                    else:
                        logging.debug(f"No IP match found in line: {original_line}")
    total_ipv4 = len(ip_entries_ipv4)
    total_ipv6 = len(ip_entries_ipv6)
    logging.info(f"Total IPv4 IP entries extracted for country code '{country_code}': {total_ipv4}")
    logging.info(f"Total IPv6 IP entries extracted for country code '{country_code}': {total_ipv6}")
    return ip_entries_ipv4, ip_entries_ipv6

def generate_rsc_and_json(ip_entries_ipv4: list, ip_entries_ipv6: list, country_code: str, output_dir: Path):
    """
    Generates a unified .rsc file containing both IPv4 and IPv6 entries,
    and a JSON file containing all extracted IP entries.

    Args:
        ip_entries_ipv4 (list): List of IPv4 entries.
        ip_entries_ipv6 (list): List of IPv6 entries.
        country_code (str): The country code.
        output_dir (Path): Directory to save the output files.
    """
    rsc_file = output_dir / f"{country_code}.rsc"
    json_file = output_dir / f"{country_code}.json"
    logging.info(f"Generating .rsc file: {rsc_file}")
    try:
        with open(rsc_file, 'w') as f_rsc:
            # Write IPv4 entries
            if ip_entries_ipv4:
                f_rsc.write("/ip firewall address-list\n")
                for entry in ip_entries_ipv4:
                    comment = f"{country_code}.{entry['organization']} - {entry['date']}"
                    rsc_line = f'add address={entry["ip"]} list={country_code} comment="{comment}"\n'
                    f_rsc.write(rsc_line)
                    logging.debug(f"Wrote to {rsc_file}: {rsc_line.strip()}")

            # Write IPv6 entries
            if ip_entries_ipv6:
                f_rsc.write("\n/ipv6 firewall address-list\n")
                for entry in ip_entries_ipv6:
                    comment = f"{country_code}.{entry['organization']} - {entry['date']}"
                    rsc_line = f'add address={entry["ip"]} list={country_code} comment="{comment}"\n'
                    f_rsc.write(rsc_line)
                    logging.debug(f"Wrote to {rsc_file}: {rsc_line.strip()}")

        logging.info(f".rsc file '{rsc_file}' generated successfully.")

    except Exception as e:
        logging.error(f"Failed to write to .rsc file: {e}")
        sys.exit(1)

    # Generate JSON file
    logging.info(f"Generating JSON file: {json_file}")
    try:
        all_entries = ip_entries_ipv4 + ip_entries_ipv6
        with open(json_file, 'w') as f_json:
            json.dump(all_entries, f_json, indent=4)
        logging.info(f"JSON file '{json_file}' generated successfully with {len(all_entries)} entries.")
    except Exception as e:
        logging.error(f"Failed to write to JSON file: {e}")
        sys.exit(1)

def main():
    """
    Main function to orchestrate the IP extraction and file generation.
    """
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Extract IP ranges for a given country code and generate MikroTik .rsc and JSON files.")
    parser.add_argument('--country', required=True, help="Two-letter ISO country code (e.g., 'ad', 'ir').")
    args = parser.parse_args()

    country_code = args.country.lower()

    # Validate country code format
    if not re.match(r'^[a-z]{2}$', country_code):
        print("Error: Country code must be a two-letter ISO code (e.g., 'ad', 'ir').")
        sys.exit(1)

    # Define URLs and paths
    alloclist_url = "https://ftp.ripe.net/ripe/stats/membership/alloclist.txt"
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    log_file = output_dir / "ip_extraction.log"

    # Set up logging
    setup_logging(log_file)

    logging.info(f"Starting IP extraction for country code: {country_code}")

    # Download alloclist.txt
    lines = download_alloclist(alloclist_url)

    # Parse alloclist.txt
    ip_entries_ipv4, ip_entries_ipv6 = parse_alloclist(lines, country_code)

    if not ip_entries_ipv4 and not ip_entries_ipv6:
        logging.warning(f"No IP entries found for country code '{country_code}'.")
        print(f"No IP entries found for country code '{country_code}'. Check the log for details.")
        sys.exit(0)

    # Generate .rsc and JSON files
    generate_rsc_and_json(ip_entries_ipv4, ip_entries_ipv6, country_code, output_dir)

    logging.info("IP extraction and file generation completed successfully.")
    print(f".rsc and JSON files for country code '{country_code}' have been generated in the 'output/' directory.")

if __name__ == "__main__":
    main()

