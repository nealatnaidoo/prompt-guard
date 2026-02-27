"""CLI entry point for running the Prompt Guard service."""

import argparse
import uvicorn

from .utils.config import load_config


def main():
    parser = argparse.ArgumentParser(description="Prompt Guard — content protection middleware")
    parser.add_argument("--host", default=None, help="Bind host")
    parser.add_argument("--port", type=int, default=None, help="Bind port")
    parser.add_argument("--config", default=None, help="Path to config YAML")
    parser.add_argument("--workers", type=int, default=None, help="Number of workers")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    config = load_config(args.config)
    service_cfg = config.get("service", {})

    uvicorn.run(
        "prompt_guard.src.middleware.app:app",
        host=args.host or service_cfg.get("host", "0.0.0.0"),
        port=args.port or service_cfg.get("port", 8420),
        workers=args.workers or service_cfg.get("workers", 4),
        log_level=service_cfg.get("log_level", "info"),
        reload=args.reload,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
