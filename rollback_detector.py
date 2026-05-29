from dataclasses import dataclass


@dataclass
class RollbackHardeningResult:
    rollback_possible: bool
    version_marker_present: bool
    monotonic_counter_present: bool
    signature_check_present: bool
    boot_validation_present: bool
    confidence: str
    reason: str


class RollbackHardeningTester:
    VERSION_MARKERS = [
        b"Betaflight",
        b"VERSION",
        b"FW_VERSION",
        b"BUILD",
    ]

    COUNTER_MARKERS = [
        b"counter",
        b"build_num",
        b"rollback",
        b"min_version",
    ]

    SIGNATURE_MARKERS = [
        b"CRC",
        b"sha256",
        b"signature",
        b"verify",
        b"checksum",
    ]

    BOOT_VALIDATION_MARKERS = [
        b"boot",
        b"reset",
        b"vector",
        b"validate",
    ]

    def marker_exists(self, blob: bytes, markers):
        blob_lower = blob.lower()
        return any(marker.lower() in blob_lower for marker in markers)

    def analyze(self, blob: bytes):
        has_version = self.marker_exists(blob, self.VERSION_MARKERS)
        has_counter = self.marker_exists(blob, self.COUNTER_MARKERS)
        has_sig = self.marker_exists(blob, self.SIGNATURE_MARKERS)
        has_boot = self.marker_exists(blob, self.BOOT_VALIDATION_MARKERS)

        rollback_possible = not (has_counter and has_sig and has_boot)

        confidence = "LOW"
        if rollback_possible:
            confidence = "HIGH" if not has_counter else "MEDIUM"

        reasons = []

        if not has_counter:
            reasons.append(
                "No monotonic version counter was found, meaning older vulnerable "
                "Betaflight builds may be reflashed without resistance."
            )

        if not has_sig:
            reasons.append(
                "Strong version signature or checksum validation markers are missing, "
                "reducing assurance that only trusted firmware revisions are accepted."
            )

        if not has_boot:
            reasons.append(
                "Boot-stage validation indicators are weak, increasing the chance that "
                "rollback firmware may execute before trust checks intervene."
            )

        if not reasons:
            reasons.append(
                "Rollback protection anchors such as counters, integrity checks, and "
                "boot validation surfaces appear present."
            )

        return RollbackHardeningResult(
            rollback_possible=rollback_possible,
            version_marker_present=has_version,
            monotonic_counter_present=has_counter,
            signature_check_present=has_sig,
            boot_validation_present=has_boot,
            confidence=confidence,
            reason=" ".join(reasons)
        )