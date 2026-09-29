from __future__ import annotations

import pytest

fitz = pytest.importorskip("pymupdf")

from tools.measure_whitespace import (
    empty_grid,
    exceeds_vertical_void_limit,
    find_voids,
    qualifying_voids,
)


def test_blank_white_a4_page_is_detected_as_a_large_void() -> None:
    document = fitz.open()
    page = document.new_page(width=842, height=595)

    grid, cols, rows, mm_per_cell = empty_grid(
        page, dpi=150, margin_mm=(10, 15), cell_mm=2
    )
    voids = find_voids(grid, cols, rows, mm_per_cell, min_void_mm=20)

    assert voids
    largest = max(voids, key=lambda item: item["width_mm"] * item["height_mm"])
    assert largest["width_mm"] > 60
    assert largest["height_mm"] > 60


def test_pale_card_background_does_not_hide_an_empty_area() -> None:
    document = fitz.open()
    page = document.new_page(width=842, height=595)
    page.draw_rect(fitz.Rect(60, 60, 400, 400), color=None, fill=(0.96, 0.97, 0.98))

    grid, cols, rows, mm_per_cell = empty_grid(
        page, dpi=150, margin_mm=(10, 15), cell_mm=2
    )
    voids = find_voids(grid, cols, rows, mm_per_cell, min_void_mm=20)

    assert voids
    assert max(item["width_mm"] for item in voids) > 60
    assert max(item["height_mm"] for item in voids) > 60


def test_light_chart_track_is_treated_as_designed_content_on_white_page() -> None:
    document = fitz.open()
    page = document.new_page(width=842, height=595)
    page.draw_rect(fitz.Rect(180, 150, 360, 330), color=None, fill=(0.94, 0.95, 0.96))

    grid, cols, rows, mm_per_cell = empty_grid(
        page, dpi=150, margin_mm=(10, 15), cell_mm=2
    )
    voids = find_voids(grid, cols, rows, mm_per_cell, min_void_mm=20)

    assert any(not cell for row in grid for cell in row)
    assert voids


def test_page_wide_but_short_gap_is_not_treated_as_a_long_vertical_void() -> None:
    assert not exceeds_vertical_void_limit(
        [{"width_mm": 278.0, "height_mm": 24.0}], max_height_mm=60.0
    )
    assert exceeds_vertical_void_limit(
        [{"width_mm": 278.0, "height_mm": 61.0}], max_height_mm=60.0
    )


def test_wraparound_connected_component_is_not_mistaken_for_one_large_hole() -> None:
    regions = [
        {"width_mm": 278.0, "height_mm": 96.0, "cells": 1171, "fill_ratio": 0.18},
        {"width_mm": 278.0, "height_mm": 22.0, "cells": 1507, "fill_ratio": 1.0},
    ]

    assert qualifying_voids(regions) == [regions[1]]
