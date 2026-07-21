#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.ls_keystore_utils.decorators."""

import pytest
from pathlib import Path

from logstashagent.ls_keystore_utils.decorators import to_path, pathify, path_exists


class TestToPath:
    def test_string_converts_to_path(self):
        result = to_path("/tmp/file.txt")
        assert isinstance(result, Path)
        assert result == Path("/tmp/file.txt")

    def test_path_object_is_returned_unchanged(self):
        p = Path("/tmp")
        result = to_path(p)
        assert result is p

    def test_none_is_returned_unchanged(self):
        assert to_path(None) is None

    def test_integer_is_returned_unchanged(self):
        assert to_path(42) == 42

    def test_list_is_returned_unchanged(self):
        lst = [1, 2, 3]
        assert to_path(lst) is lst

    def test_bytes_non_path_on_windows_left_unchanged(self):
        # On Windows bytes are NOT path-like so to_path returns them unchanged.
        # On POSIX they may convert but we just check the function doesn't raise.
        result = to_path(b"/some/path")
        assert result is not None  # either a Path or the original bytes


class TestPathify:
    def test_converts_string_arg_to_path(self, tmp_path):
        @pathify("src")
        def func(src):
            return src

        result = func(str(tmp_path))
        assert isinstance(result, Path)

    def test_passes_path_arg_through(self, tmp_path):
        @pathify("src")
        def func(src):
            return src

        result = func(tmp_path)
        assert result == tmp_path

    def test_converts_default_string_to_path(self):
        @pathify("dst")
        def func(dst="/output/default"):
            return dst

        result = func()
        assert isinstance(result, Path)
        assert result == Path("/output/default")

    def test_converts_multiple_named_args(self, tmp_path):
        @pathify("src", "dst")
        def func(src, dst):
            return src, dst

        src_str = str(tmp_path)
        dst_str = str(tmp_path / "out")
        src_out, dst_out = func(src_str, dst_str)
        assert isinstance(src_out, Path)
        assert isinstance(dst_out, Path)

    def test_non_convertible_value_left_alone(self):
        @pathify("p")
        def func(p=None):
            return p

        assert func() is None

    def test_works_with_keyword_arguments(self, tmp_path):
        @pathify("src")
        def func(src):
            return src

        result = func(src=str(tmp_path))
        assert isinstance(result, Path)

    def test_preserves_function_name_and_doc(self):
        @pathify("p")
        def my_func(p):
            """My docstring."""
            return p

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "My docstring."


class TestPathExists:
    def test_raises_file_not_found_for_missing_file(self, tmp_path):
        @pathify("p")
        @path_exists("p", kind="is_file")
        def func(p):
            return p

        with pytest.raises(FileNotFoundError):
            func(str(tmp_path / "nonexistent.txt"))

    def test_raises_file_not_found_for_missing_dir(self, tmp_path):
        @pathify("p")
        @path_exists("p", kind="is_dir")
        def func(p):
            return p

        with pytest.raises(FileNotFoundError):
            func(str(tmp_path / "nosuchdir"))

    def test_passes_for_existing_file(self, tmp_path):
        real_file = tmp_path / "real.txt"
        real_file.write_text("data")

        @pathify("p")
        @path_exists("p", kind="is_file")
        def func(p):
            return p

        result = func(str(real_file))
        assert isinstance(result, Path)

    def test_passes_for_existing_dir(self, tmp_path):
        @pathify("p")
        @path_exists("p", kind="is_dir")
        def func(p):
            return p

        result = func(str(tmp_path))
        assert isinstance(result, Path)

    def test_raises_type_error_for_non_path_arg(self):
        @path_exists("p")
        def func(p):
            return p

        with pytest.raises(TypeError):
            func(42)

    def test_invalid_kind_raises_value_error(self):
        with pytest.raises(ValueError, match="kind must be one of"):
            path_exists("p", kind="invalid_kind")

    def test_exists_kind_checks_path_exists(self, tmp_path):
        @pathify("p")
        @path_exists("p", kind="exists")
        def func(p):
            return p

        existing = tmp_path / "afile.txt"
        existing.write_text("hi")
        assert func(str(existing)) == existing

        with pytest.raises(FileNotFoundError):
            func(str(tmp_path / "missing"))

    def test_stacked_with_pathify_file(self, tmp_path):
        """pathify + path_exists work correctly when stacked."""
        real_file = tmp_path / "data.bin"
        real_file.write_bytes(b"\x00\x01")

        @pathify("filename")
        @path_exists("filename", kind="is_file")
        def read_bytes(filename: Path) -> bytes:
            return filename.read_bytes()

        assert read_bytes(str(real_file)) == b"\x00\x01"
