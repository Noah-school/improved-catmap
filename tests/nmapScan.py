import sys
import os
import asyncio
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import nmapScan

async def test_nmapScan():
    host = '192.168.0.1'
    args = '-T4 -A -n -Pn'
    host, result = await nmapScan(host, args)
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    asyncio.run(test_nmapScan())
