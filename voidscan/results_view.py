"""Helpers for paging and filtering large terminal result lists."""

from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


def filter_items(
    items: Sequence[T],
    query: str,
    text: Callable[[T], str],
) -> list[T]:
    """Return items whose text contains the query, ignoring case."""

    needle = query.strip().casefold()

    if not needle:
        return list(items)

    return [item for item in items if needle in text(item).casefold()]


def page_count(total: int, page_size: int) -> int:
    """Return how many pages are needed for a number of items."""

    if total <= 0:
        return 1

    return (total + page_size - 1) // page_size


def clamp_page(page: int, total: int, page_size: int) -> int:
    """Keep a page number inside the valid range."""

    return min(max(page, 1), page_count(total, page_size))


def page_items(
    items: Sequence[T],
    page: int,
    page_size: int,
) -> list[T]:
    """Return one clamped page of items."""

    total = len(items)
    start = (clamp_page(page, total, page_size) - 1) * page_size

    return list(items[start : start + page_size])
