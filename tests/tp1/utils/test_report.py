from unittest.mock import patch, MagicMock
from src.tp1.utils.report import Report


def _make_report():

    capture = MagicMock()
    capture.protocols = {"TCP": 10, "UDP": 3}
    capture.alerts = []
    return Report(capture, "report.pdf", "test summary")


# --- concat_report ---

def test_when_report_created_then_concat_report_contains_title():

    report = _make_report()


    result = report.concat_report()


    assert report.title in result


def test_when_report_created_then_concat_report_contains_summary():

    report = _make_report()


    result = report.concat_report()


    assert "test summary" in result


# --- generate array ---

def test_when_generate_array_then_array_is_not_empty():

    report = _make_report()


    report.generate("array")


    assert report.array != ""
    assert len(report.array) == 2  # TCP + UDP


def test_when_no_alerts_then_all_protocols_are_legitimate():

    report = _make_report()


    report.generate("array")


    for proto, count, status in report.array:
        assert status == "Legitimate"


def test_when_alert_on_tcp_then_tcp_marked_suspicious():

    capture = MagicMock()
    capture.protocols = {"TCP": 10}
    capture.alerts = [{"protocol": "TCP", "type": "Port Scan",
                        "src_ip": "1.2.3.4", "src_mac": "N/A", "detail": "..."}]
    report = Report(capture, "report.pdf", "")


    report.generate("array")


    proto, count, status = report.array[0]
    assert status == "Suspicious"


# --- generate graph ---

def test_when_generate_graph_with_empty_protocols_then_graph_stays_empty():

    capture = MagicMock()
    capture.protocols = {}
    capture.alerts = []
    report = Report(capture, "report.pdf", "")

    report.generate("graph")


    assert report.graph == ""