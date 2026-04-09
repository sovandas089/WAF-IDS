import httpx
import asyncio
import time

WAF_URL = "http://localhost:8085"

async def test_sqli():
    print("Testing SQL Injection Payload...")
    async with httpx.AsyncClient() as client:
        # Send a malicious payload in query
        res = await client.get(f"{WAF_URL}/login?user=' OR 1=1 --")
        if res.status_code == 403:
            print("SUCCESS: WAF blocked SQLi!")
        else:
            print(f"FAILED: WAF allowed SQLi. Status {res.status_code}")

async def test_xss():
    print("Testing XSS Payload...")
    async with httpx.AsyncClient() as client:
        # Send an XSS payload
        res = await client.post(f"{WAF_URL}/comment", json={"text": "<script>alert(1)</script>"})
        if res.status_code == 403:
            print("SUCCESS: WAF blocked XSS!")
        else:
            print(f"FAILED: WAF allowed XSS. Status {res.status_code}")

async def test_brute_force():
    print("Testing Brute Force (Sending 25 requests rapidly)...")
    async with httpx.AsyncClient() as client:
        blocked = False
        for i in range(25):
            res = await client.get(f"{WAF_URL}/")
            if res.status_code == 403:
                print(f"SUCCESS: WAF triggered block on request {i+1}!")
                blocked = True
                break
        
        if not blocked:
            print("FAILED: WAF did not block brute force.")

async def main():
    print("Starting WAF Tests...\n")
    await test_sqli()
    await asyncio.sleep(1)
    await test_xss()
    await asyncio.sleep(1)
    await test_brute_force()

if __name__ == "__main__":
    asyncio.run(main())
