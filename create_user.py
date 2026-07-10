#!/usr/bin/env python3
"""
CLI tool to create VulnChain user accounts.
Usage: python create_user.py --username analyst --password yourpassword
"""
import argparse
from app import create_app
from app.auth import register_user
from app.models import get_user_by_username


def main():
    parser = argparse.ArgumentParser(description="Create a VulnChain user account")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    app = create_app()
    db_path = app.config["DB_PATH"]

    if get_user_by_username(db_path, args.username):
        print(f"[!] User '{args.username}' already exists.")
        return

    register_user(db_path, args.username, args.password)
    print(f"[+] User '{args.username}' created successfully.")
    print(f"    Password is bcrypt hashed with 12 rounds.")
    print(f"    Login at: http://localhost:5000/login")


if __name__ == "__main__":
    main()
