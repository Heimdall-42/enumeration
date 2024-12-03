
# Enumeration Script

This Python script automates the enumeration of hosts. It uses tools like Nmap and FFUF to discover open ports, directories, subdomains, and virtual hosts. The script provides interactive options to add new subdomains to the `/etc/hosts` file and automatically performs additional scans.

---

## Requirements

### Operating System
- Linux-based systems (tested on Ubuntu and Kali Linux).

### Tools and Dependencies
Ensure the following tools are installed on your system:
1. **Python 3.x**
2. **Nmap**
3. **FFUF**
4. **sudo** (for modifications to `/etc/hosts`)

You can check if the tools are installed using the `which` command, e.g.:
```bash
which nmap ffuf sudo
```

### Python Dependencies
No additional Python libraries are required as only standard libraries are used.

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <REPOSITORY_URL>
   cd <REPOSITORY_FOLDER>
   ```

2. **Set File Permissions**:
   Ensure the script is executable:
   ```bash
   chmod +x enumeration.py
   ```

3. **Install Tools (if necessary)**:
   - **Debian/Ubuntu**:
     ```bash
     sudo apt update
     sudo apt install nmap ffuf
     ```
   - **Arch**:
     ```bash
     sudo pacman -S nmap ffuf
     ```

---

## Usage

1. **Run the Script**:
   ```bash
   python3 enumeration.py
   ```

2. **Input Prompts**:
   The script will prompt for:
   - `Machine Name`: The name of the machine, e.g., `example`.
   - `Machine IP`: The IP address of the machine, e.g., `10.10.10.10`.

3. **Interactivity**:
   - The script asks if newly discovered subdomains should be added to the `/etc/hosts` file.
   - Once confirmed, additional directory scans for these subdomains are automatically performed.

---

## Outputs

- **Scan Results**:
  Results are saved in the directory named after the machine. For example:
  ```
  /example/
  ├── example_ffuf_dir_80.txt
  ├── example_ffuf_sub_80.txt
  ├── example_ffuf_vhost_80.txt
  └── example_nmap_scan.xml
  ```

- **Logs**:
  All actions and errors are logged in `enumeration.log`.

---

## Customization

1. **Adjust Wordlists**:
   - Directories: The default wordlist is `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`.
   - Subdomains: The default wordlist is `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`.
   You can modify these paths in the script if you want to use other wordlists.

2. **Error Codes for FFUF**:
   If the target uses different HTTP error codes (e.g., `403` or `404`), update the filter option (`-fc`) in the code:
   ```python
   filters="401,402,403,404"
   ```

3. **Host File**:
   - Modifications to `/etc/hosts` require `sudo`.
   - The script checks for existing entries before adding new ones.

4. **Parallelization**:
   You can adjust the number of threads for scans in `ThreadPoolExecutor()`:
   ```python
   with ThreadPoolExecutor(max_workers=10) as executor:
   ```

---

## Important Notes

- **Authorization**:
  Only use this script on systems where you have explicit permission to perform these tests.
- **Performance**:
  Large wordlists can significantly increase runtime. Reduce the wordlist size if needed.
- **Rate Limiting**:
  Some servers may block your IP if too many requests are made. Adjust the number of threads or wordlists accordingly.

---

## Example Output

```
Enter the machine name: example
Enter the machine IP address: 10.10.10.10
Starting Nmap scan...
Parsing Nmap results...
Open ports: [(80, 'http'), (443, 'https')]
Starting FFUF scans...
Found VHost subdomain: admin.example.htb. Add to /etc/hosts? (yes/no): yes
Added admin.example.htb to /etc/hosts.
Started directory scan for new subdomain: admin.example.htb
Enumeration complete. Check logs and output files.
```

---

## Contact

If you have questions or encounter issues, open an issue on GitHub or contact the repository maintainer.
