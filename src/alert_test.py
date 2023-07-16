from alert import Alert, AlertDescription, AlertLevel


def test_alert_to_bytes():
    alert = Alert(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)
    assert bytes(alert) == b"\x02\x28"


def test_alert_from_bytes():
    alert = Alert.from_bytes(b"\x02\x28")
    assert alert.level == AlertLevel.FATAL
    assert alert.description == AlertDescription.HANDSHAKE_FAILURE
