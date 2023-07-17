from alert import Alert, Description, Level


def test_alert_to_bytes():
    alert = Alert(Level.FATAL, Description.HANDSHAKE_FAILURE)
    assert bytes(alert) == b"\x02\x28"


def test_alert_from_bytes():
    alert = Alert.from_bytes(b"\x02\x28")
    assert alert.level == Level.FATAL
    assert alert.description == Description.HANDSHAKE_FAILURE
