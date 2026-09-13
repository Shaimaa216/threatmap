def _truthy(value):
    return value is True or str(value).lower() in {"true", "1", "yes"}

def calculate_risk(data: dict) -> dict:
    """
    ThreatMap application-level heuristic.
    It uses only security/proxy/usage fields returned by IP2Location.io.
    It does not assert that an IP is malicious.
    """
    score = 0
    reasons = []
    proxy = data.get("proxy") or {}

    if _truthy(proxy.get("is_tor")):
        score += 35
        reasons.append("Tor indicator detected")

    if _truthy(proxy.get("is_vpn")):
        score += 25
        reasons.append("VPN indicator detected")

    if _truthy(proxy.get("is_public_proxy")):
        score += 25
        reasons.append("Public proxy detected")

    if _truthy(proxy.get("is_web_proxy")):
        score += 20
        reasons.append("Web proxy detected")

    if _truthy(proxy.get("is_residential_proxy")):
        score += 18
        reasons.append("Residential proxy detected")

    if _truthy(proxy.get("is_spammer")):
        score += 35
        reasons.append("Spammer indicator detected")

    if _truthy(proxy.get("is_web_crawler")):
        score += 10
        reasons.append("Web crawler indicator detected")

    if _truthy(proxy.get("is_ai_crawler")):
        score += 8
        reasons.append("AI crawler indicator detected")

    if _truthy(proxy.get("is_consumer_privacy_network")):
        score += 20
        reasons.append("Consumer privacy network indicator detected")

    threat = proxy.get("threat")
    if threat and str(threat).strip().lower() not in {"-", "none", "unknown", "n/a"}:
        score += 30
        reasons.append(f"Threat indicator reported: {threat}")

    usage = str(data.get("usage_type") or "").upper()
    if usage == "DCH" or _truthy(proxy.get("is_data_center")):
        score += 15
        reasons.append("Data center/hosting usage detected")

    score = min(100, max(0, score))
    if score <= 29:
        level = "Low Risk"
    elif score <= 59:
        level = "Medium Risk"
    else:
        level = "High Risk"

    if not reasons:
        reasons.append("No elevated proxy/threat indicators were reported")

    return {"risk_score": score, "risk_level": level, "reasons": reasons}
