"""Characterisation tests for src/cli.py — CLI entry point."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from src.cli import main


class TestCliArgumentParsing:
    """Verify argparse configuration and default values."""

    @patch("src.cli.uvicorn")
    @patch("src.cli.load_config", return_value={})
    def test_default_arguments(self, mock_config, mock_uvicorn):
        """With no CLI args, defaults come from empty config fallback."""
        with patch.object(sys, "argv", ["prompt-guard"]):
            main()

        mock_uvicorn.run.assert_called_once_with(
            "prompt_guard.src.middleware.app:app",
            host="0.0.0.0",
            port=8420,
            workers=4,
            log_level="info",
            reload=False,
        )

    @patch("src.cli.uvicorn")
    @patch("src.cli.load_config", return_value={})
    def test_custom_host_and_port(self, mock_config, mock_uvicorn):
        """CLI --host and --port override defaults."""
        with patch.object(sys, "argv", ["prompt-guard", "--host", "127.0.0.1", "--port", "9000"]):
            main()

        call_kwargs = mock_uvicorn.run.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 9000

    @patch("src.cli.uvicorn")
    @patch("src.cli.load_config", return_value={})
    def test_workers_argument(self, mock_config, mock_uvicorn):
        """CLI --workers overrides default."""
        with patch.object(sys, "argv", ["prompt-guard", "--workers", "8"]):
            main()

        call_kwargs = mock_uvicorn.run.call_args[1]
        assert call_kwargs["workers"] == 8

    @patch("src.cli.uvicorn")
    @patch("src.cli.load_config", return_value={})
    def test_reload_flag(self, mock_config, mock_uvicorn):
        """CLI --reload enables auto-reload."""
        with patch.object(sys, "argv", ["prompt-guard", "--reload"]):
            main()

        call_kwargs = mock_uvicorn.run.call_args[1]
        assert call_kwargs["reload"] is True

    @patch("src.cli.uvicorn")
    @patch("src.cli.load_config", return_value={})
    def test_config_path_passed_to_load_config(self, mock_config, mock_uvicorn):
        """CLI --config is forwarded to load_config."""
        with patch.object(sys, "argv", ["prompt-guard", "--config", "/tmp/custom.yaml"]):
            main()

        mock_config.assert_called_once_with("/tmp/custom.yaml")

    @patch("src.cli.uvicorn")
    @patch("src.cli.load_config", return_value={})
    def test_config_none_when_not_provided(self, mock_config, mock_uvicorn):
        """When --config is omitted, None is passed to load_config."""
        with patch.object(sys, "argv", ["prompt-guard"]):
            main()

        mock_config.assert_called_once_with(None)


class TestCliConfigOverrides:
    """Verify that YAML config values are used when CLI args are not provided."""

    @patch("src.cli.uvicorn")
    @patch(
        "src.cli.load_config",
        return_value={
            "service": {
                "host": "10.0.0.1",
                "port": 7777,
                "workers": 2,
                "log_level": "debug",
            }
        },
    )
    def test_config_values_used_as_defaults(self, mock_config, mock_uvicorn):
        """Service config values are used when CLI args are absent."""
        with patch.object(sys, "argv", ["prompt-guard"]):
            main()

        mock_uvicorn.run.assert_called_once_with(
            "prompt_guard.src.middleware.app:app",
            host="10.0.0.1",
            port=7777,
            workers=2,
            log_level="debug",
            reload=False,
        )

    @patch("src.cli.uvicorn")
    @patch(
        "src.cli.load_config",
        return_value={
            "service": {"host": "10.0.0.1", "port": 7777}
        },
    )
    def test_cli_args_override_config(self, mock_config, mock_uvicorn):
        """CLI arguments take precedence over config file values."""
        with patch.object(sys, "argv", ["prompt-guard", "--host", "0.0.0.0", "--port", "9999"]):
            main()

        call_kwargs = mock_uvicorn.run.call_args[1]
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 9999


class TestCliErrorCases:
    """Verify error handling for invalid arguments."""

    def test_invalid_port_type(self):
        """Non-integer --port causes argparse to exit."""
        with patch.object(sys, "argv", ["prompt-guard", "--port", "not-a-number"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_invalid_workers_type(self):
        """Non-integer --workers causes argparse to exit."""
        with patch.object(sys, "argv", ["prompt-guard", "--workers", "abc"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_unknown_argument(self):
        """Unknown arguments cause argparse to exit."""
        with patch.object(sys, "argv", ["prompt-guard", "--unknown-flag"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    @patch("src.cli.uvicorn")
    @patch("src.cli.load_config", return_value={})
    def test_help_flag_exits_zero(self, mock_config, mock_uvicorn):
        """--help causes a clean exit with code 0."""
        with patch.object(sys, "argv", ["prompt-guard", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
