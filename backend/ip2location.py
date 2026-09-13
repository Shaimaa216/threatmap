import ipaddress
import httpx

from .config import IP2LOCATION_API_KEY, IP2LOCATION_BASE_URL, REQUEST_TIMEOUT

class IP2LocationError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code

def validate_ip(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("IP address is required.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("Invalid IPv4 or IPv6 address.")

async def lookup_ip(ip: str) -> dict:
    ip = validate_ip(ip)
    if not IP2LOCATION_API_KEY:
        raise IP2LocationError(
            "IP2LOCATION_API_KEY is not configured. Copy .env.example to .env and add your key."
        )

    params = {"key": IP2LOCATION_API_KEY, "ip": ip, "format": "json"}
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(IP2LOCATION_BASE_URL, params=params)
    except httpx.TimeoutException:
        raise IP2LocationError("IP2Location request timed out.")
    except httpx.RequestError:
        raise IP2LocationError("Could not reach IP2Location.io.")

    if response.status_code == 429:
        raise IP2LocationError("IP2Location rate limit reached. Please try again later.", 429)
    if response.status_code >= 500:
        raise IP2LocationError("IP2Location service is temporarily unavailable.", response.status_code)
    if response.status_code >= 400:
        try:
            detail = response.json().get("error", {}).get("message")
        except Exception:
            detail = None
        raise IP2LocationError(detail or "IP2Location rejected the request.", response.status_code)

    try:
        data = response.json()
    except ValueError:
        raise IP2LocationError("IP2Location returned an invalid response.")

    if data.get("error"):
        error = data["error"]
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise IP2LocationError(message or "IP2Location returned an error.")

    return data
