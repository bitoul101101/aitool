from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from services.access_control import UserContext, filter_projects


@dataclass(frozen=True)
class SingleUserConfig:
    name: str
    expected_bitbucket_owner: str
    ctx: UserContext


def load_single_user_config(path: str) -> SingleUserConfig:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Single-user access config is required: {exc}") from exc

    operator = data.get("operator")
    if not isinstance(operator, dict):
        raise RuntimeError("access_control.json must define an 'operator' object")

    name = str(operator.get("name", "")).strip()
    if not name:
        raise RuntimeError("access_control.json operator.name is required")

    roles = tuple(str(r).strip().lower() for r in operator.get("roles", []) if str(r).strip())
    projects = tuple(str(p).strip() for p in operator.get("projects", []) if str(p).strip())
    if not roles:
        raise RuntimeError("access_control.json operator.roles must not be empty")
    if not projects:
        raise RuntimeError("access_control.json operator.projects must not be empty")

    return SingleUserConfig(
        name=name,
        expected_bitbucket_owner=str(operator.get("bitbucket_owner", "")).strip(),
        ctx=UserContext(username=name, roles=roles, allowed_projects=projects),
    )


@dataclass
class SingleUserState:
    config: SingleUserConfig
    client: Any | None = None
    connected_owner: str = "Unknown"
    projects_cache: list[dict] = field(default_factory=list)
    repos_cache: dict[str, list[dict]] = field(default_factory=dict)

    @property
    def ctx(self) -> UserContext:
        return self.config.ctx

    def public_auth(self) -> dict[str, Any]:
        return {
            "user": self.ctx.username,
            "roles": list(self.ctx.roles),
            "projects": list(self.ctx.allowed_projects),
        }

    def can(self, role: str) -> bool:
        return self.ctx.can(role)

    def can_access_project(self, project_key: str) -> bool:
        return self.ctx.can_access_project(project_key)

    def connect(self, client: Any, owner: str, projects: list[dict]) -> list[dict]:
        owner = (owner or "Unknown").strip() or "Unknown"
        expected = self.config.expected_bitbucket_owner
        if expected and owner != expected:
            raise PermissionError(
                f"Connected PAT owner '{owner}' does not match configured operator '{expected}'"
            )
        self.client = client
        self.connected_owner = owner
        self.projects_cache = filter_projects(projects, self.ctx)
        self.repos_cache.clear()
        return list(self.projects_cache)
