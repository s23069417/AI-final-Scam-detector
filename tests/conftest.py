"""Shared test setup."""

import pytest


@pytest.fixture(autouse=True)
def no_network_for_links(monkeypatch):
    """Tests never touch the network: the link inspector runs offline by default.

    A test that wants the "online" path sets its own fake resolver (see test_links.py).
    """
    monkeypatch.setenv("SCAM_LINKS_OFFLINE", "1")
