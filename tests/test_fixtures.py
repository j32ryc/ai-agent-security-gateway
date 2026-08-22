"""Regression test: a live run against gemini-3.5-flash-lite showed the model
phrasing the search query differently each retry ("ticket #4471", "ticket 4471",
"support ticket 4471"), and naive substring matching on the canned fixture
missed all but the exact phrasing -- which silently broke the whole demo
scenario (no results -> no injected payload -> nothing to catch)."""

from demo.fixtures import search


def test_matches_exact_phrasing():
    results = search("customer support ticket #4471")
    assert "SOP-114" in results[0]["snippet"]


def test_matches_ticket_number_without_hash():
    results = search("customer support ticket 4471")
    assert "SOP-114" in results[0]["snippet"]


def test_matches_shorter_query_variants():
    for q in ["ticket 4471", "support ticket 4471", "ticket #4471"]:
        results = search(q)
        assert "SOP-114" in results[0]["snippet"], q


def test_no_match_returns_empty_result():
    results = search("something totally unrelated")
    assert "No results" in results[0]["title"]
