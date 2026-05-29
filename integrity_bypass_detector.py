from dataclasses import dataclass


@dataclass
class IntegrityBypassResult:
    integrity_bypass_possible: bool
    vector_table_valid: bool
    reset_handler_valid: bool
    weak_validation_surface: bool
    config_integrity_surface_present: bool
    confidence: str
    reason: str


class IntegrityBypassDetector:
    VALIDATION_MARKERS = [
        b"crc",
        b"checksum",
        b"verify",
        b"magic",
        b"config",
    ]

    def check_vector_table(self, blob: bytes):
        if len(blob) < 8:
            return False, False

        sp = int.from_bytes(blob[0:4], "little")
        reset = int.from_bytes(blob[4:8], "little")

        vector_ok = 0x20000000 <= sp <= 0x20040000
        reset_ok = 0x08000000 <= reset <= 0x08100000

        return vector_ok, reset_ok

    def marker_exists(self, blob: bytes, markers):
        blob_lower = blob.lower()
        return any(marker.lower() in blob_lower for marker in markers)

    def analyze(self, blob: bytes):
        vector_ok, reset_ok = self.check_vector_table(blob)
        validation = self.marker_exists(blob, self.VALIDATION_MARKERS)

        bypass_possible = not (vector_ok and reset_ok and validation)

        confidence = "LOW"
        if not vector_ok or not reset_ok:
            confidence = "HIGH"
        elif bypass_possible:
            confidence = "MEDIUM"

        reasons = []

        if not vector_ok:
            reasons.append(
                "The initial stack pointer is outside the expected RAM region, "
                "which may indicate vector table corruption or malicious redirection."
            )

        if not reset_ok:
            reasons.append(
                "The reset handler points outside the valid flash memory range. "
                "This strongly suggests control-flow hijacking during early boot."
            )

        if not validation:
            reasons.append(
                "Weak checksum or configuration validation markers were found, "
                "reducing trust in firmware integrity enforcement."
            )

        if not reasons:
            reasons.append(
                "Vector table, reset handler, and integrity markers appear valid, "
                "indicating strong firmware trust anchors."
            )

        return IntegrityBypassResult(
            integrity_bypass_possible=bypass_possible,
            vector_table_valid=vector_ok,
            reset_handler_valid=reset_ok,
            weak_validation_surface=not validation,
            config_integrity_surface_present=validation,
            confidence=confidence,
            reason=" ".join(reasons)
        )