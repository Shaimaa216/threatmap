import os
from dotenv import load_dotenv

load_dotenv()

IP2LOCATION_API_KEY = os.getenv("IP2LOCATION_API_KEY", "").strip()
IP2LOCATION_BASE_URL = "https://api.ip2location.io/"
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))
