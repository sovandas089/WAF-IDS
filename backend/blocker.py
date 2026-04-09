import subprocess
import logging

logging.basicConfig(level=logging.INFO)

def block_ip(ip_address: str):
    """
    Adds a Windows Firewall rule to block the specified IP address.
    Requires Administrator privileges.
    """
    rule_name = f"WAF_Block_{ip_address}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip="{ip_address}"'
    
    try:
        # Run the command to block the IP
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"Successfully blocked IP: {ip_address}")
            return True, f"Blocked {ip_address}"
        else:
            logging.error(f"Failed to block IP {ip_address}: {result.stderr}")
            if "requested operation requires elevation" in result.stdout:
                return False, "Failed: Requires Administrator privileges"
            return False, result.stdout
    except Exception as e:
        logging.error(f"Exception while blocking IP {ip_address}: {e}")
        return False, str(e)
