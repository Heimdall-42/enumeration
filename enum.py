import os
import re
import subprocess
import logging
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    filename="enumeration.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def check_tool_availability(tool_name):
    result = subprocess.run(["which", tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0
def run_command_silently(command, output_file):
    if not os.path.exists(output_file):
        try:
            with open(output_file, "w") as f:
                subprocess.run(command, stdout=f, stderr=subprocess.PIPE, check=True)
                logging.info(f"Command {' '.join(command)} completed. Output saved to {output_file}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Command {command} failed: {e}")
    else:
        logging.info(f"Skipping command {' '.join(command)} as {output_file} already exists.")
def add_to_hosts(entry):
    try:
        with open("/etc/hosts", "r") as file:
            hosts_content = file.read()
        if entry not in hosts_content:
            subprocess.run(['sudo', 'tee', '-a', '/etc/hosts'], input=f"{entry}\n", text=True, check=True)
            logging.info(f"Added {entry} to /etc/hosts.")
    except Exception as e:
        logging.error(f"Failed to update /etc/hosts: {e}")
def validate_domain(domain):
    return re.match(r'^[a-zA-Z0-9_.-]+$', domain)
def parse_nmap_results(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        open_ports = []
        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                state = port.find("state").get("state")
                service = port.find("service").get("name")
                if state == "open":
                    open_ports.append((port_id, service))
        return open_ports
    except Exception as e:
        logging.error(f"Failed to parse Nmap results: {e}")
        return []
def run_ffuf(target_url, wordlist, output_file, filters="401,402,403,404"):
    if not os.path.exists(output_file):
        command = [
            "ffuf", "-u", target_url,
            "-w", wordlist, "-o", output_file,
            "-of", "csv", "-fc", filters
        ]
        logging.info(f"Running FFUF command: {' '.join(command)}")
        run_command_silently(command, output_file)
def handle_vhost_results(vhost_output, machine_name, machine_ip, port):
    try:
        new_domains = []
        if os.path.exists(vhost_output):
            with open(vhost_output, "r") as f:
                next(f)
                for line in f:
                    if "," in line:
                        subdomain = line.split(",")[0].strip()
                        full_domain = f"{subdomain}.{machine_name}.htb"
                        user_input = input(f"Found VHost subdomain: {full_domain}. Add to /etc/hosts? (yes/no): ").strip().lower()
                        if user_input in ["yes", "y"]:
                            add_to_hosts(f"{machine_ip} {full_domain}")
                            new_domains.append(full_domain)
                            print(f"Added {full_domain} to /etc/hosts.")
                            sub_dir_output = f"{full_domain}_ffuf_dir_{port}.txt"
                            sub_base_url = f"http://{full_domain}:{port}/FUZZ"
                            run_ffuf(sub_base_url, "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt", sub_dir_output)
                            print(f"Started directory scan for new subdomain: {full_domain}")
        return new_domains
    except Exception as e:
        logging.error(f"Failed to process VHost results from {vhost_output}: {e}")
        return []

# Main logic
def main():
    machine_name = input("Enter the machine name: ").strip()
    machine_ip = input("Enter the machine IP address: ").strip()
    if not validate_domain(machine_name):
        print("Invalid machine name. Use only alphanumeric characters, dots, underscores, and dashes.")
        return
    if not re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', machine_ip):
        print("Invalid IP address format.")
        return
    os.makedirs(machine_name, exist_ok=True)
    os.chdir(machine_name)
    add_to_hosts(f"{machine_ip} {machine_name}.htb")
    # Nmap scan
    nmap_output_file = f"{machine_name}_nmap_scan.xml"
    if not os.path.exists(nmap_output_file):
        print("Starting Nmap scan...")
        nmap_command = ["nmap", "-A", "-p-", "-T4", "-oX", nmap_output_file, machine_ip]
        subprocess.run(nmap_command, check=True)
    open_ports = parse_nmap_results(nmap_output_file)
    logging.info(f"Open ports: {open_ports}")
    new_vhost_domains = []
    with ThreadPoolExecutor() as executor:
        futures = []
        for port, service in open_ports:
            if service in ["http", "https"]:
                # Directory scan
                dir_output = f"{machine_name}_ffuf_dir_{port}.txt"
                base_url = f"http://{machine_name}.htb:{port}/FUZZ"
                futures.append(executor.submit(run_ffuf, base_url, "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt", dir_output))

                # Subdomain scan
                sub_output = f"{machine_name}_ffuf_sub_{port}.txt"
                subdomain_url = f"http://FUZZ.{machine_name}.htb:{port}"
                futures.append(executor.submit(run_ffuf, subdomain_url, "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", sub_output))

                # VHost scan
                vhost_output = f"{machine_name}_ffuf_vhost_{port}.txt"
                vhost_url = f"http://{machine_name}.htb:{port}"
                vhost_command = [
                    "ffuf", "-u", vhost_url,
                    "-H", f"Host: FUZZ.{machine_name}.htb",
                    "-w", "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
                    "-o", vhost_output, "-of", "csv", "-fc", "301,401,402,404"
                ]
                if not os.path.exists(vhost_output):
                    logging.info(f"Starting VHost scan on {vhost_url}.")
                    futures.append(executor.submit(run_command_silently, vhost_command, vhost_output))
                else:
                    logging.info(f"Skipping VHost scan as {vhost_output} already exists.")

        for future in futures:
            future.result()
        # Process VHost results and handle new subdomains
        for port, service in open_ports:
            if service in ["http", "https"]:
                vhost_output = f"{machine_name}_ffuf_vhost_{port}.txt"
                new_domains = handle_vhost_results(vhost_output, machine_name, machine_ip, port)
                # Immediately trigger directory scans for new subdomains
                for domain in new_domains:
                    sub_dir_output = f"{domain}_ffuf_dir_{port}.txt"
                    sub_base_url = f"http://{domain}:{port}/FUZZ"
                    with ThreadPoolExecutor() as rescan_executor:
                        rescan_executor.submit(
                            run_ffuf,
                            sub_base_url,
                            "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
                            sub_dir_output
                        )
    # Run directory scans for newly added VHost subdomains
    with ThreadPoolExecutor() as rescan_executor:
        rescan_futures = []
        for domain in new_vhost_domains:
            for port, service in open_ports:
                if service in ["http", "https"]:
                    sub_dir_output = f"{domain}_ffuf_dir_{port}.txt"
                    sub_base_url = f"http://{domain}:{port}/FUZZ"
                    rescan_futures.append(rescan_executor.submit(run_ffuf, sub_base_url, "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt", sub_dir_output))

        for future in rescan_futures:
            future.result()

    print("Enumeration complete. Check logs and output files.")

if __name__ == "__main__":
    main()
