import subprocess
import os
import time

def block_ip(ip_address: str, duration_minutes: int = 15) -> tuple[bool, str]:
    """
    Blocks an IP address using Windows Advanced Firewall and records it to the database with a 15-minute timeout.
    """
    if os.name != "nt":
        return False, "Firewall blocking is only supported on Windows OS for this prototype."

    rule_name = f"WAF_Block_{ip_address}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            # Save to Database for Auto-Unblocking
            from backend.database import SessionLocal
            from backend.models import BlockHistory
            try:
                with SessionLocal() as db:
                    unblock_time = time.time() + (duration_minutes * 60)
                    new_block = BlockHistory(ip=ip_address, unblock_time=unblock_time, reason="Score limit exceeded")
                    db.add(new_block)
                    db.commit()
            except Exception as e:
                pass # Already blocked or unique constraint failed
                
            return True, f"Successfully inserted firewall block rule for {ip_address} (Temp: {duration_minutes}m)."
        else:
            return False, f"Failed to run firewall command: {result.stderr}"
    except Exception as e:
        return False, f"Exception occurred while blocking IP: {str(e)}"

def unblock_ip(ip_address: str) -> bool:
    """Removes a blocked IP from the Windows Firewall."""
    if os.name != "nt": return False
    rule_name = f"WAF_Block_{ip_address}"
    command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    try:
        subprocess.run(command, shell=True, capture_output=True, text=True)
        return True
    except:
        return False

def check_expired_blocks():
    """Queries persistent database for expired IP blocks and unblocks them."""
    from backend.database import SessionLocal
    from backend.models import BlockHistory
    from backend.analyzer import blocked_ips # Safe import
    try:
        with SessionLocal() as db:
            current_time = time.time()
            expired = db.query(BlockHistory).filter(BlockHistory.unblock_time <= current_time).all()
            for record in expired:
                ip = record.ip
                unblock_ip(ip)
                if ip in blocked_ips:
                    blocked_ips.remove(ip)
                db.delete(record)
            db.commit()
    except Exception as e:
        pass
