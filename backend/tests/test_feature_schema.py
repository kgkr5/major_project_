"""Tests for the feature schema (single source of truth)."""

from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES, FEATURE_INDEX


def test_feature_count_is_77():
    assert FEATURE_COUNT == 77, f"Expected 77 features, got {FEATURE_COUNT}"


def test_no_duplicate_feature_names():
    assert len(set(FEATURE_NAMES)) == 77, "Duplicate feature names detected"


def test_feature_index_matches_list():
    for i, name in enumerate(FEATURE_NAMES):
        assert FEATURE_INDEX[name] == i, (
            f"Feature '{name}' index mismatch: FEATURE_INDEX={FEATURE_INDEX[name]}, expected={i}"
        )


def test_feature_index_length():
    assert len(FEATURE_INDEX) == 77


def test_no_empty_feature_names():
    for name in FEATURE_NAMES:
        assert name.strip(), f"Empty feature name detected: '{name}'"
