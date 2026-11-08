from kpis import SLA_DAYS, age_bucket, risk_band, tile_status


def test_sla_days():
    assert SLA_DAYS == {"Critical": 7, "High": 30, "Medium": 90}


def test_age_bucket_edges():
    assert age_bucket(0) == "0-30 days"
    assert age_bucket(30) == "0-30 days"
    assert age_bucket(31) == "31-60 days"
    assert age_bucket(60) == "31-60 days"
    assert age_bucket(90) == "61-90 days"
    assert age_bucket(91) == "90+ days"


def test_risk_band_edges():
    assert risk_band(1) == "Low"
    assert risk_band(6) == "Low"
    assert risk_band(8) == "Medium"
    assert risk_band(12) == "Medium"
    assert risk_band(15) == "High"
    assert risk_band(25) == "High"


def test_tile_status_higher_is_better():
    assert tile_status("sla_pct", 95) == "good"
    assert tile_status("sla_pct", 90) == "good"
    assert tile_status("sla_pct", 85) == "warn"
    assert tile_status("sla_pct", 79) == "bad"


def test_tile_status_lower_is_better():
    assert tile_status("phish_click", 8) == "good"
    assert tile_status("phish_click", 12) == "warn"
    assert tile_status("phish_click", 16) == "bad"
    assert tile_status("patch_latency", 14) == "good"
    assert tile_status("patch_latency", 22) == "bad"
