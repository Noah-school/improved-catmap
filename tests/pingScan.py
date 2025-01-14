import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
from main import pingscan

results = asyncio.run(pingscan(True, '192.168.0.0/24', wait=1, count=4))
print(len(results))