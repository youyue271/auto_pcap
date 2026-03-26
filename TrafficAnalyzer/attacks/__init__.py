from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.attacks.behinder_detector import BehinderDetector
from TrafficAnalyzer.attacks.port_scan_detector import PortScanDetector
from TrafficAnalyzer.attacks.sql_injection_detector import SQLInjectionDetector


def build_attack_detectors() -> list[BaseAttackDetector]:
    return [
        PortScanDetector(threshold=10, time_window=5.0),
        SQLInjectionDetector(),
        BehinderDetector(),
    ]


__all__ = [
    "BaseAttackDetector",
    "PortScanDetector",
    "SQLInjectionDetector",
    "BehinderDetector",
    "build_attack_detectors",
]

