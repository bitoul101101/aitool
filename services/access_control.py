from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


ROLE_VIEWER = "viewer"
ROLE_SCANNER = "scanner"
ROLE_TRIAGE = "triage"
ROLE_ADMIN = "admin"

ALL_ROLES = {ROLE_VIEWER, ROLE_SCANNER, ROLE_TRIAGE, ROLE_ADMIN}
DEFAULT_BOOTSTRAP_ROLES = [ROLE_VIEWER, ROLE_SCANNER, ROLE_TRIAGE, ROLE_ADMIN]


@dataclass(frozen=True)
class UserContext:
    username: str
    roles: tuple[str, ...]
    allowed_projects: tuple[str, ...]

    def can(self, role: str) -> bool:
        return role in self.roles

    def can_access_project(self, project_key: str) -> bool:
        return "*" in self.allowed_projects or project_key in self.allowed_projects


def load_access_control(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def resolve_user_context(path: str, username: str) -> UserContext:
    username = (username or "Unknown").strip() or "Unknown"
    cfg = load_access_control(path)
    users = cfg.get("users", {})
    entry = users.get(username, {})
    if not isinstance(entry, dict):
        entry = {}

    roles = _normalise_roles(entry.get("roles") or cfg.get("default_roles") or DEFAULT_BOOTSTRAP_ROLES)
    projects = _normalise_projects(entry.get("projects") or cfg.get("default_projects") or ["*"])
    return UserContext(username=username, roles=tuple(roles), allowed_projects=tuple(projects))


def filter_projects(projects: list[dict], ctx: UserContext) -> list[dict]:
    if "*" in ctx.allowed_projects:
        return list(projects)
    return [p for p in projects if str(p.get("key", "")) in ctx.allowed_projects]


def _normalise_roles(raw_roles) -> list[str]:
    roles = []
    for role in raw_roles if isinstance(raw_roles, list) else []:
        value = str(role).strip().lower()
        if value in ALL_ROLES and value not in roles:
            roles.append(value)
    if not roles:
        roles = list(DEFAULT_BOOTSTRAP_ROLES)
    return roles


def _normalise_projects(raw_projects) -> list[str]:
    projects = []
    for project in raw_projects if isinstance(raw_projects, list) else []:
        value = str(project).strip()
        if value and value not in projects:
            projects.append(value)
    if not projects:
        return ["*"]
    return projects
