"""Small, strict JSON Schema subset used by configured harness responses.

Supported keywords are deliberately explicit: type, properties, required,
additionalProperties, enum, items, minItems, maxItems, minLength, maxLength.
Unknown keywords fail closed instead of pretending validation occurred.
"""

from __future__ import annotations

from typing import Any

_SUPPORTED = {
    "type", "properties", "required", "additionalProperties", "enum", "items",
    "minItems", "maxItems", "minLength", "maxLength", "description", "title",
}
_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


def validate_json_schema(instance: Any, schema: dict[str, Any] | None, path: str = "$") -> None:
    if schema is None:
        return
    if not isinstance(schema, dict):
        raise ValueError("schema must be an object")
    unknown = set(schema) - _SUPPORTED
    if unknown:
        raise ValueError(f"unsupported schema keywords: {sorted(unknown)}")
    expected = schema.get("type")
    if expected is not None:
        if expected not in _TYPES:
            raise ValueError(f"unsupported schema type: {expected}")
        expected_type = _TYPES[expected]
        if expected in {"number", "integer"} and isinstance(instance, bool):
            raise ValueError(f"{path}: expected {expected}")
        if not isinstance(instance, expected_type):
            raise ValueError(f"{path}: expected {expected}")
    if "enum" in schema and instance not in schema["enum"]:
        raise ValueError(f"{path}: value is not in enum")
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ValueError("schema properties must be an object")
        required = schema.get("required", [])
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            raise ValueError("schema required must be a string array")
        missing = [key for key in required if key not in instance]
        if missing:
            raise ValueError(f"{path}: missing required properties {missing}")
        extras = set(instance) - set(properties)
        additional = schema.get("additionalProperties", True)
        if additional is False and extras:
            raise ValueError(f"{path}: additional properties {sorted(extras)}")
        if additional not in {True, False} and not isinstance(additional, dict):
            raise ValueError("additionalProperties must be boolean or schema")
        for key, value in instance.items():
            child = properties.get(key)
            if child is None and isinstance(additional, dict):
                child = additional
            if child is not None:
                validate_json_schema(value, child, f"{path}.{key}")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < int(schema["minItems"]):
            raise ValueError(f"{path}: too few items")
        if "maxItems" in schema and len(instance) > int(schema["maxItems"]):
            raise ValueError(f"{path}: too many items")
        if "items" in schema:
            for index, item in enumerate(instance):
                validate_json_schema(item, schema["items"], f"{path}[{index}]")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < int(schema["minLength"]):
            raise ValueError(f"{path}: string too short")
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            raise ValueError(f"{path}: string too long")
