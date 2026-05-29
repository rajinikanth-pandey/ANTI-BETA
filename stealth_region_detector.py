from dataclasses import dataclass


@dataclass
class StealthRegionResult:
    stealth_region_detected: bool
    suspicious_offsets: list[str]
    deviation_count: int
    confidence: str
    reason: str


class StealthRegionDetector:
    def analyze(self, baseline_offsets, current_changes):
        baseline_set = set(baseline_offsets)
        current_offsets = [c["offset"] for c in current_changes]

        suspicious = [
            off for off in current_offsets
            if off not in baseline_set
        ]

        detected = len(suspicious) > 0

        confidence = "LOW"
        if len(suspicious) > 16:
            confidence = "HIGH"
        elif detected:
            confidence = "MEDIUM"

        if detected:
            reason = (
                f"{len(suspicious)} modified offsets were found outside the trusted "
                "baseline mutation profile. This suggests hidden firmware changes in "
                "unexpected memory regions, which may indicate stealth implants, "
                "covert persistence, or malicious drift beyond normal Betaflight updates."
            )
        else:
            reason = (
                "All detected firmware changes remain within previously learned trusted "
                "regions, indicating behavior consistent with normal update patterns."
            )

        return StealthRegionResult(
            stealth_region_detected=detected,
            suspicious_offsets=suspicious,
            deviation_count=len(suspicious),
            confidence=confidence,
            reason=reason
        )