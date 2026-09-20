"""Optional Redis advisory transport (never authoritative)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from exceptions import RedisConfigurationError

REQUIRED_PREFIX = "td:p1:"


@dataclass(frozen=True)
class RedisAdvisoryConfig:
    url: str
    acl_user: str
    prefix: str = REQUIRED_PREFIX

    def __post_init__(self) -> None:
        if not self.acl_user or not self.prefix.startswith(REQUIRED_PREFIX):
            raise RedisConfigurationError(
                "Redis requires dedicated ACL user and td:p1: prefix"
            )


class RedisAdvisory:
    """Fail-closed advisory mirror; PostgreSQL remains authoritative."""

    def __init__(self, config: RedisAdvisoryConfig | None) -> None:
        self._config = config
        self._client: Any = None
        if config is not None:
            try:
                import redis
            except ImportError as exc:
                raise RedisConfigurationError("redis package is not installed") from exc
            self._client = redis.Redis.from_url(config.url, username=config.acl_user)

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def ping(self) -> bool:
        if not self.enabled:
            return True
        try:
            return bool(self._client.ping())
        except Exception as exc:
            raise RedisConfigurationError("Redis advisory transport is unavailable") from exc

    def validate_key(self, key: str) -> str:
        if self._config is None:
            raise RedisConfigurationError("Redis is disabled")
        if not key.startswith(self._config.prefix):
            raise RedisConfigurationError(f"key must use prefix {self._config.prefix}")
        return key

    def set_status(self, key: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        full_key = self.validate_key(key)
        try:
            self._client.set(full_key, json.dumps(payload, sort_keys=True))
        except Exception as exc:
            raise RedisConfigurationError("Redis advisory write failed") from exc

    def get_status(self, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        full_key = self.validate_key(key)
        try:
            raw = self._client.get(full_key)
        except Exception as exc:
            raise RedisConfigurationError("Redis advisory read failed") from exc
        if raw is None:
            return None
        return json.loads(raw)

    def delete_namespace(self) -> int:
        if not self.enabled:
            return 0
        pattern = f"{self._config.prefix}*"
        deleted = 0
        try:
            for key in self._client.scan_iter(match=pattern):
                self._client.delete(key)
                deleted += 1
        except Exception as exc:
            raise RedisConfigurationError("Redis advisory namespace cleanup failed") from exc
        return deleted

    @classmethod
    def from_env(cls, *, enabled: bool, url: str | None, acl_user: str | None) -> RedisAdvisory:
        if not enabled:
            return cls(None)
        if not url or not acl_user:
            raise RedisConfigurationError(
                "Redis enabled without dedicated ACL user and URL"
            )
        advisory = cls(RedisAdvisoryConfig(url=url, acl_user=acl_user))
        advisory.ping()
        return advisory
