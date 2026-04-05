from unittest.mock import patch, MagicMock
from src.tp1.utils.capture import Capture


def _make_capture():

    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0"):
        return Capture()


# --- gen_summary ---

def test_when_no_packets_then_summary_contains_zero():

    capture = _make_capture()


    result = capture.gen_summary()


    assert "0" in result


def test_when_no_alerts_then_summary_contains_no_illegitimate_traffic():

    capture = _make_capture()


    result = capture.gen_summary()


    assert "No illegitimate traffic detected." in result


# --- get_all_protocols ---

def test_when_protocols_set_then_get_all_protocols_returns_them():

    capture = _make_capture()
    capture.protocols = {"TCP": 10, "UDP": 5}


    result = capture.get_all_protocols()


    assert result == {"TCP": 10, "UDP": 5}


def test_when_no_protocols_then_get_all_protocols_returns_empty_dict():

    capture = _make_capture()


    result = capture.get_all_protocols()

    assert result == {}


# --- get_summary ---

def test_when_summary_set_then_get_summary_returns_it():

    capture = _make_capture()
    capture.summary = "test summary"


    result = capture.get_summary()


    assert result == "test summary"


# --- sort_network_protocols ---

def test_when_packets_empty_then_sort_network_protocols_sets_empty_dict():

    capture = _make_capture()
    capture.packets = []


    capture.sort_network_protocols()

    assert capture.protocols == {}


# --- _record_alert (dédoublonnage) ---

def test_when_same_alert_twice_then_only_one_recorded():

    capture = _make_capture()


    capture._record_alert("Port Scan", "TCP", "1.2.3.4", "aa:bb", "detail")
    capture._record_alert("Port Scan", "TCP", "1.2.3.4", "aa:bb", "detail")


    assert len(capture.alerts) == 1


def test_when_different_ips_then_two_alerts_recorded():

    capture = _make_capture()


    capture._record_alert("Port Scan", "TCP", "1.2.3.4", "aa:bb", "detail")
    capture._record_alert("Port Scan", "TCP", "5.6.7.8", "cc:dd", "detail")


    assert len(capture.alerts) == 2