from dataclasses import dataclass


@dataclass
class CovertChannelResult:
    covert_channel_possible: bool
    hidden_cli_markers: bool
    suspicious_serial_markers: bool
    hidden_msp_markers: bool
    telemetry_abuse_possible: bool
    confidence: str
    reason: str


class CovertChannelDetector:
    CLI_MARKERS = [
        b"cli",
        b"serialpassthrough",
        b"dump",
        b"flash_info",
        b"flash_erase",
    ]

    SERIAL_MARKERS = [
        b"UART",
        b"USART",
        b"serial",
        b"usb",
        b"CDC",
    ]

    MSP_MARKERS = [
        b"MSP",
        b"mspProcess",
        b"mspSerial",
        b"mspCommand",
    ]

    TELEMETRY_MARKERS = [
        b"CRSF",
        b"ELRS",
        b"SMARTPORT",
        b"TELEMETRY",
        b"BLACKBOX",
    ]

    def marker_exists(self, blob: bytes, markers):
        blob_lower = blob.lower()
        return any(marker.lower() in blob_lower for marker in markers)

    def analyze(self, blob: bytes):
        cli = self.marker_exists(blob, self.CLI_MARKERS)
        serial = self.marker_exists(blob, self.SERIAL_MARKERS)
        msp = self.marker_exists(blob, self.MSP_MARKERS)
        telemetry = self.marker_exists(blob, self.TELEMETRY_MARKERS)

        covert_possible = (
            (cli and serial)
            or (msp and serial)
            or telemetry
        )

        confidence = "LOW"
        if covert_possible:
            confidence = "HIGH" if telemetry and msp else "MEDIUM"

        reasons = []

        if cli:
            reasons.append(
                "CLI control surfaces are present, which may allow hidden command execution "
                "or stealth firmware interaction."
            )

        if serial:
            reasons.append(
                "Serial/UART communication handlers are embedded, creating a possible covert "
                "transport layer for hidden data exchange."
            )

        if msp:
            reasons.append(
                "MSP command interfaces were detected. In Betaflight, MSP is a powerful control "
                "channel that can be abused for stealth command-and-control."
            )

        if telemetry:
            reasons.append(
                "Telemetry protocols such as CRSF, ELRS, SMARTPORT, or BLACKBOX are present, "
                "which may be repurposed for covert exfiltration or hidden beaconing."
            )

        if not reasons:
            reasons.append(
                "No significant covert communication markers were identified in the firmware."
            )

        return CovertChannelResult(
            covert_channel_possible=covert_possible,
            hidden_cli_markers=cli,
            suspicious_serial_markers=serial,
            hidden_msp_markers=msp,
            telemetry_abuse_possible=telemetry,
            confidence=confidence,
            reason=" ".join(reasons)
        )