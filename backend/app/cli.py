"""Administrative commands.

    python -m app.cli create-user admin@example.org --role admin
    python -m app.cli migrate
"""
import argparse
import getpass
import sys

from sqlalchemy import select

from app.core.models import Role, User
from app.core.security import hash_password, validate_password_strength
from app.db.database import SessionLocal, init_db


def create_user(email: str, role: str, full_name: str) -> int:
    init_db()
    password = getpass.getpass("Password: ")
    if problem := validate_password_strength(password):
        print(problem, file=sys.stderr)
        return 1
    if password != getpass.getpass("Repeat password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == email.lower())):
            print(f"{email} already exists.", file=sys.stderr)
            return 1
        db.add(User(email=email.lower(), full_name=full_name, password_hash=hash_password(password), role=Role(role)))
        db.commit()
    print(f"Created {role} {email}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user")
    create.add_argument("email")
    create.add_argument("--role", choices=[r.value for r in Role], default=Role.analyst.value)
    create.add_argument("--name", default="")
    sub.add_parser("migrate")
    args = parser.parse_args()
    if args.command == "create-user":
        return create_user(args.email, args.role, args.name)
    init_db()
    print("Database schema is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
