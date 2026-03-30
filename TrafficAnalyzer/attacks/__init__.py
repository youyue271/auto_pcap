from TrafficAnalyzer.config import ATTACK_DETECTOR_PATHS, DETECTOR_CONFIGS
from TrafficAnalyzer.core.factory import build_instances
from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.attacks.behinder_detector import BehinderDetector
from TrafficAnalyzer.attacks.port_scan_detector import PortScanDetector
from TrafficAnalyzer.attacks.sql_injection_detector import SQLInjectionDetector


def build_attack_detectors() -> list[BaseAttackDetector]:
    return build_instances(ATTACK_DETECTOR_PATHS, configs=DETECTOR_CONFIGS)


__all__ = [
    "BaseAttackDetector",
    "PortScanDetector",
    "SQLInjectionDetector",
    "BehinderDetector",
    "build_attack_detectors",
]
