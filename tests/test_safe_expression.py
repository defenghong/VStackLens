from vstacklens.rules.safe_expression import SafeExpressionEngine


def test_starts_with_and_not_starts_with() -> None:
    engine = SafeExpressionEngine()
    assert engine.evaluate("name starts_with 'ESXi'", {"name": "ESXi-01"})
    assert engine.evaluate("name not starts_with 'ESXi'", {"name": "vCenter-01"})
    assert not engine.evaluate("name not starts_with 'ESXi'", {"name": "ESXi-01"})


def test_contains_and_not_contains() -> None:
    engine = SafeExpressionEngine()
    assert engine.evaluate("text contains 'prod'", {"text": "vm-prod-01"})
    assert engine.evaluate("text not contains 'dev'", {"text": "vm-prod-01"})
    assert not engine.evaluate("text not contains 'prod'", {"text": "vm-prod-01"})


def test_length_count_distinct_and_in() -> None:
    engine = SafeExpressionEngine()
    context = {"items": ["a", "b", "b"], "state": "connected"}
    assert engine.evaluate("items.length == 3", context)
    assert engine.evaluate("items.count_distinct == 2", context)
    assert engine.evaluate("state in ['connected', 'maintenance']", context)


def test_json_style_literals_are_normalized_safely() -> None:
    engine = SafeExpressionEngine()

    assert engine.evaluate("enabled == true", {"enabled": True})
    assert engine.evaluate("enabled == false", {"enabled": False})
    assert engine.evaluate("value is null", {"value": None})
    assert engine.evaluate("value is not null", {"value": "present"})


def test_literal_normalization_does_not_rewrite_names_or_strings() -> None:
    engine = SafeExpressionEngine()
    context = {
        "is_true_flag": True,
        "text": "true",
        "other": "false",
        "obj": {"true_value": "kept"},
    }

    assert engine.evaluate("is_true_flag == true", context)
    assert engine.evaluate("text == 'true'", context)
    assert engine.evaluate('other == "false"', context)
    assert engine.evaluate("obj.true_value == 'kept'", context)
