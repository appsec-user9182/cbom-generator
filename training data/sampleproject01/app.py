"""
CloudKMS — Cloud Key Management Service

A REST-like API for managing cryptographic keys, performing encryption/decryption,
and issuing digital signatures and certificates.

Supported API versions:
  v1  — Legacy endpoints (SHA-1 auth, DES encryption, RSA-1024 key generation)
  v2  — Modern endpoints (PBKDF2-SHA256 auth, AES-256 encryption, RSA-2048 / ECDSA)

Entry point: run this module to start the service simulation.
"""

import sys
import json
from api.routes import dispatch


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    print(f"CloudKMS starting on {host}:{port}")
    print("Available versions: v1 (legacy), v2 (current)")
    print("Press Ctrl+C to stop.")
    while True:
        try:
            raw = input("Request (method path JSON): ").strip()
            if not raw:
                continue
            parts = raw.split(" ", 2)
            if len(parts) < 2:
                print("Usage: METHOD /path/route {\"key\": \"value\"}")
                continue
            method = parts[0].upper()
            path = parts[1]
            body = json.loads(parts[2]) if len(parts) == 3 else {}
            method_path = f"{method} {path}"
            response = dispatch(method_path, body)
            print(json.dumps(response, indent=2))
        except KeyboardInterrupt:
            print("\nShutting down.")
            break
        except Exception as exc:
            print(f"Error: {exc}")


def handle_cli_request(argv: list[str]) -> dict:
    if len(argv) < 3:
        print("Usage: python app.py METHOD /path/route '{\"key\":\"value\"}'")
        sys.exit(1)
    method = argv[1].upper()
    path = argv[2]
    body = json.loads(argv[3]) if len(argv) > 3 else {}
    method_path = f"{method} {path}"
    return dispatch(method_path, body)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--serve":
        result = handle_cli_request(sys.argv)
        print(json.dumps(result, indent=2))
    else:
        run_server()
