from dataclasses import dataclass


@dataclass
class MasqueradeResult:
    masquerade_possible: bool
    task_identity_surface: bool
    cli_identity_surface: bool
    msp_identity_surface: bool
    telemetry_identity_surface: bool
    confidence: str
    reason: str


class MasqueradeDetector:
    TASK_MARKERS = [
        b"CLI",
        b"MSP",
        b"BLACKBOX",
        b"GYRO",
        b"OSD",
        b"TASK",
    ]

    CLI_MARKERS = [
        b"dump",
        b"diff",
        b"profile",
        b"feature",
        b"defaults",
    ]

    MSP_MARKERS = [
        b"MSP",
        b"mspCommand",
        b"mspProcess",
    ]

    TELEMETRY_MARKERS = [
        b"CRSF",
        b"ELRS",
        b"SMARTPORT",
        b"BLACKBOX",
    ]

    def marker_exists(self, blob: bytes, markers):
        blob_lower = blob.lower()
        return any(marker.lower() in blob_lower for marker in markers)

    def analyze(self, blob: bytes):
        task = self.marker_exists(blob, self.TASK_MARKERS)
        cli = self.marker_exists(blob, self.CLI_MARKERS)
        msp = self.marker_exists(blob, self.MSP_MARKERS)
        telemetry = self.marker_exists(blob, self.TELEMETRY_MARKERS)

        possible = task or cli or msp or telemetry

        confidence = "LOW"
        if task and cli and telemetry:
            confidence = "HIGH"
        elif possible:
            confidence = "MEDIUM"

        reasons = []

        if task:
            reasons.append(
                "Trusted scheduler or runtime task identities were detected, which may be "
                "used by malicious logic to disguise itself as normal Betaflight tasks."
            )

        if cli:
            reasons.append(
                "CLI command surfaces are present and may allow malicious features to "
                "blend into normal diagnostic or configuration interfaces."
            )

        if msp:
            reasons.append(
                "MSP command handlers were found, creating an opportunity for stealth "
                "payloads to masquerade as legitimate Betaflight control commands."
            )

        if telemetry:
            reasons.append(
                "Telemetry-related identities such as CRSF, ELRS, SMARTPORT, or BLACKBOX "
                "can be abused to camouflage covert payload behavior."
            )

        if not reasons:
            reasons.append(
                "No strong masquerade identity surfaces were detected in the firmware."
            )

        return MasqueradeResult(
            masquerade_possible=possible,
            task_identity_surface=task,
            cli_identity_surface=cli,
            msp_identity_surface=msp,
            telemetry_identity_surface=telemetry,
            confidence=confidence,
            reason=" ".join(reasons)
        )