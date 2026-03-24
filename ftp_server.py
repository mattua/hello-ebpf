#!/usr/bin/env python3
import os
import shutil
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

FTP_HOST = os.environ.get("HELLO_FTP_HOST", "127.0.0.1")
FTP_PORT = int(os.environ.get("HELLO_FTP_PORT", "2121"))
FTP_USER = os.environ.get("HELLO_FTP_USER", "bonduser")
FTP_PASS = os.environ.get("HELLO_FTP_PASS", "bondpass")
REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE_FILE = REPO_ROOT / "ACME_EOD_BondPrices.csv"
DEFAULT_FTP_ROOT = REPO_ROOT / ".ftp_root"
FTP_ROOT = Path(os.environ.get("HELLO_FTP_ROOT", str(DEFAULT_FTP_ROOT))).resolve()


def prepare_default_root() -> Path:
    FTP_ROOT.mkdir(exist_ok=True)

    if FTP_ROOT == DEFAULT_FTP_ROOT:
        for child in FTP_ROOT.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

        shutil.copy2(DEFAULT_SOURCE_FILE, FTP_ROOT / DEFAULT_SOURCE_FILE.name)

    return FTP_ROOT


def create_server() -> FTPServer:
    ftp_root = prepare_default_root()
    authorizer = DummyAuthorizer()
    authorizer.add_user(FTP_USER, FTP_PASS, str(ftp_root), perm="elr")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "hello-ebpf FTP server ready"
    handler.passive_ports = range(30000, 30001)

    return FTPServer((FTP_HOST, FTP_PORT), handler)


def main() -> None:
    server = create_server()
    print(f"serving FTP on {FTP_HOST}:{FTP_PORT} root={FTP_ROOT} user={FTP_USER}")
    server.serve_forever()


if __name__ == "__main__":
    main()
