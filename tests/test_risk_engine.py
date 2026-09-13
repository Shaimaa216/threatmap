from backend.risk_engine import calculate_risk

def test_low_risk():
    result = calculate_risk({"is_proxy": False, "usage_type": "ISP"})
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low Risk"

def test_high_risk_proxy_and_tor():
    result = calculate_risk({
        "usage_type": "DCH",
        "proxy": {"is_tor": True, "is_vpn": True, "is_spammer": True, "threat": "Known threat"}
    })
    assert result["risk_score"] >= 60
    assert result["risk_level"] == "High Risk"

def test_medium_data_center():
    result = calculate_risk({"usage_type": "DCH", "proxy": {}})
    assert result["risk_score"] == 15
    assert result["risk_level"] == "Low Risk"
