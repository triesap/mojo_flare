"""Unit tests for the OpenAPI 3.1 spec emitter."""

from std.testing import assert_equal, assert_true
from json import loads

from flare.openapi import (
    OpenApiOperation,
    OpenApiParameter,
    OpenApiPath,
    OpenApiResponse,
    OpenApiSpec,
    emit_openapi_json,
)


def test_minimal_spec_round_trips_through_json_parser() raises:
    """The simplest legal OpenAPI 3.1 document: title + version
    + empty paths. The emitter output must be valid JSON that
    re-parses cleanly through Mojo's stdlib JSON parser."""
    var spec = OpenApiSpec.new(String("Test API"), String("1.0.0"))
    var s = emit_openapi_json(spec)
    var j = loads(s)
    assert_true(j.is_object())
    assert_equal(j["openapi"].string_value(), String("3.1.0"))
    var info = j["info"]
    assert_equal(info["title"].string_value(), String("Test API"))
    assert_equal(info["version"].string_value(), String("1.0.0"))


def test_path_with_get_operation() raises:
    """A single GET /users operation with one query parameter and
    two responses (200, default)."""
    var spec = OpenApiSpec.new(String("Users API"), String("2.0"))
    var params = List[OpenApiParameter]()
    params.append(
        OpenApiParameter(
            name=String("limit"),
            location=String("query"),
            required=False,
            schema_type=String("integer"),
        )
    )
    var responses = List[OpenApiResponse]()
    responses.append(
        OpenApiResponse(
            status=String("200"),
            description=String("List of users"),
            content_type=String("application/json"),
        )
    )
    responses.append(
        OpenApiResponse(
            status=String("default"),
            description=String("Unexpected error"),
            content_type=String(""),
        )
    )
    var op = OpenApiOperation(
        method=String("get"),
        summary=String("List users"),
        operation_id=String("listUsers"),
        parameters=params^,
        responses=responses^,
    )
    var ops = List[OpenApiOperation]()
    ops.append(op^)
    spec.paths.append(OpenApiPath(template=String("/users"), operations=ops^))
    var s = emit_openapi_json(spec)
    var j = loads(s)
    var paths = j["paths"]
    var users = paths["/users"]
    var get_op = users["get"]
    assert_equal(get_op["operationId"].string_value(), String("listUsers"))
    assert_equal(get_op["summary"].string_value(), String("List users"))
    var responses_obj = get_op["responses"]
    var ok_response = responses_obj["200"]
    assert_equal(
        ok_response["description"].string_value(), String("List of users")
    )


def test_json_escaping_preserves_special_chars() raises:
    """The emitter must escape backslashes, quotes, newlines, and
    control characters in user-provided strings."""
    var spec = OpenApiSpec.new(
        String('API with "quotes" and \\backslashes\\'),
        String("1.0"),
    )
    spec.info.description = String("Line 1\nLine 2")
    var s = emit_openapi_json(spec)
    var j = loads(s)
    var info = j["info"]
    assert_equal(
        info["title"].string_value(),
        String('API with "quotes" and \\backslashes\\'),
    )
    assert_equal(info["description"].string_value(), String("Line 1\nLine 2"))


def test_emitter_is_deterministic() raises:
    """Two identical specs must produce byte-identical JSON so
    caches + diffs work."""
    var s1 = OpenApiSpec.new(String("API"), String("1.0"))
    var s2 = OpenApiSpec.new(String("API"), String("1.0"))
    assert_equal(emit_openapi_json(s1), emit_openapi_json(s2))


def main() raises:
    test_minimal_spec_round_trips_through_json_parser()
    test_path_with_get_operation()
    test_json_escaping_preserves_special_chars()
    test_emitter_is_deterministic()
    print("test_openapi: OK")
