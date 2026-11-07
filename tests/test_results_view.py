"""Tests for the paging and filtering helpers."""

from voidscan.results_view import (
    clamp_page,
    filter_items,
    page_count,
    page_items,
)


def test_filter_items_matches_case_insensitive_substrings() -> None:
    values = ["api.example.com", "WWW.EXAMPLE.COM", "mail.other.net"]

    assert filter_items(values, "EXAMPLE", lambda value: value) == [
        "api.example.com",
        "WWW.EXAMPLE.COM",
    ]


def test_filter_items_with_an_empty_query_keeps_everything() -> None:
    values = ["a", "b"]

    assert filter_items(values, "", lambda value: value) == values


def test_filter_items_can_return_no_matches() -> None:
    assert filter_items(["a"], "z", lambda value: value) == []


def test_filter_items_uses_the_text_function() -> None:
    values = [{"name": "alpha"}, {"name": "beta"}]

    assert filter_items(values, "BET", lambda item: item["name"]) == [
        {"name": "beta"}
    ]


def test_page_count_handles_empty_and_exact_pages() -> None:
    assert page_count(0, 50) == 1
    assert page_count(50, 50) == 1
    assert page_count(51, 50) == 2
    assert page_count(120, 50) == 3


def test_clamp_page_keeps_the_page_in_range() -> None:
    assert clamp_page(0, 120, 50) == 1
    assert clamp_page(-3, 120, 50) == 1
    assert clamp_page(2, 120, 50) == 2
    assert clamp_page(9, 120, 50) == 3
    assert clamp_page(1, 0, 50) == 1


def test_page_items_returns_one_page() -> None:
    values = [str(index) for index in range(120)]

    assert page_items(values, 1, 50)[0] == "0"
    assert len(page_items(values, 1, 50)) == 50
    assert page_items(values, 2, 50)[0] == "50"
    assert page_items(values, 3, 50)[-1] == "119"


def test_page_items_clamps_out_of_range_pages() -> None:
    values = [str(index) for index in range(120)]

    assert page_items(values, 99, 50)[0] == "100"
    assert page_items(values, 0, 50)[0] == "0"
