from TrafficAnalyzer.config import ATTACK_DETECTOR_PATHS, DETECTOR_CONFIGS
from TrafficAnalyzer.core.factory import build_instances
from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.attacks.webshell_detector import WebShellDetector


def build_attack_detectors() -> list[BaseAttackDetector]:
    return build_instances(ATTACK_DETECTOR_PATHS, configs=DETECTOR_CONFIGS)


__all__ = [
    "BaseAttackDetector",
    "WebShellDetector",
    "build_attack_detectors",
]
