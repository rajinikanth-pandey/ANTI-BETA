from dataclasses import dataclass


@dataclass
class SecureBootBypassResult:
    bypass_possible: bool
    signature_validation_surface_missing: bool
    vector_table_boot_surface_present: bool
    dfu_boot_surface_present: bool
    anti_rollback_missing: bool
    confidence: str
    reason: str


class SecureBootBypassDetector:
    SIGNATURE_MARKERS = [
        b"signature",
        b"sha256",
        b"sha1",
        b"crc",
        b"verify",
        b"checksum",
    ]

    BOOT_MARKERS = [
        b"boot",
        b"reset",
        b"vector",
        b"hardfault",
        b"systick",
    ]

    DFU_MARKERS = [
        b"DFU",
        b"USB",
        b"bootloader",
        b"serialpassthrough",
        b"stm32",
    ]

    ANTI_ROLLBACK_MARKERS = [
        b"min_version",
        b"rollback",
        b"counter",
        b"build_num",
    ]

    def marker_exists(self, blob: bytes, markers):
        blob_lower = blob.lower()
        return any(marker.lower() in blob_lower for marker in markers)

    def analyze(self, blob: bytes):
        has_signature = self.marker_exists(blob, self.SIGNATURE_MARKERS)
        has_boot = self.marker_exists(blob, self.BOOT_MARKERS)
        has_dfu = self.marker_exists(blob, self.DFU_MARKERS)
        has_rollback = self.marker_exists(blob, self.ANTI_ROLLBACK_MARKERS)

        bypass_possible = (not has_signature) or has_dfu or (not has_rollback)

        confidence = "LOW"
        if (not has_signature) and has_dfu and (not has_rollback):
            confidence = "HIGH"
        elif bypass_possible:
            confidence = "MEDIUM"

        reasons = []

        if not has_signature:
            reasons.append(
                "Strong signature or hash verification markers are missing, which may allow "
                "unsigned or malicious Betaflight firmware images to be accepted."
            )

        if has_boot:
            reasons.append(
                "Boot control surfaces such as vector, reset, SysTick, or HardFault markers "
                "are present and may expose early trust-chain manipulation paths."
            )

        if has_dfu:
            reasons.append(
                "DFU, USB bootloader, STM32 flashing, or serial passthrough surfaces are exposed, "
                "creating a realistic firmware reflashing bypass path."
            )

        if not has_rollback:
            reasons.append(
                "Anti-rollback markers are absent, increasing the risk of replaying older "
                "vulnerable firmware revisions."
            )

        if not reasons:
            reasons.append(
                "Strong secure boot indicators, signature anchors, and rollback protection "
                "surfaces appear present."
            )

        return SecureBootBypassResult(
            bypass_possible=bypass_possible,
            signature_validation_surface_missing=not has_signature,
            vector_table_boot_surface_present=has_boot,
            dfu_boot_surface_present=has_dfu,
            anti_rollback_missing=not has_rollback,
            confidence=confidence,
            reason=" ".join(reasons)
        )