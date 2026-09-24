"""Run as the gateway service user. Read new tokens from stdin; never print them."""

import argparse
import sys

from .security import TokenStore, database_path


def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="action", required=True)
    create = actions.add_parser("create")
    create.add_argument("name")
    revoke = actions.add_parser("revoke")
    revoke.add_argument("name")
    actions.add_parser("list")
    args = parser.parse_args()
    store = TokenStore(database_path())
    if args.action == "create":
        store.add(args.name, sys.stdin.read().strip())
        print("Token hash stored for", args.name)
    elif args.action == "revoke":
        print("Revoked" if store.revoke(args.name) else "Unknown name")
    else:
        for row in store.list_tokens():
            print(row["name"], "revoked" if row["disabled"] else "active", row["created_at"])


if __name__ == "__main__":
    main()
