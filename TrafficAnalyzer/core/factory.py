from __future__ import annotations

from importlib import import_module
from typing import Any, Iterable, Mapping


def load_object(import_path: str) -> Any:
    module_path, separator, attribute_name = import_path.rpartition(".")
    if not separator:
        raise ValueError(f"无效导入路径: {import_path}")

    module = import_module(module_path)
    try:
        return getattr(module, attribute_name)
    except AttributeError as exc:
        raise ImportError(f"模块 {module_path} 中不存在对象 {attribute_name}") from exc


def build_instances(
    import_paths: Iterable[str],
    configs: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[Any]:
    config_map = configs or {}
    instances: list[Any] = []

    for import_path in import_paths:
        cls = load_object(import_path)
        kwargs = dict(config_map.get(cls.__name__, {}))
        instances.append(cls(**kwargs))

    return instances
