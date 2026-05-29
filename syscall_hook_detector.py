from dataclasses import dataclass


@dataclass
class SyscallHookResult:
    hook_possible: bool
    vector_table_exposed: bool
    callback_dispatch_present: bool
    cli_dispatch_present: bool
    msp_dispatch_present: bool
    confidence: str
    reason: str


class SyscallHookDetector:
    VECTOR_MARKERS = [
        b"HardFault",
        b"SysTick",
        b"Reset",
        b"PendSV",
        b"NMI",
    ]

    CALLBACK_MARKERS = [
        b"callback",
        b"worker",
        b"scheduler",
        b"dispatch",
        b"blx",
    ]

    CLI_MARKERS = [
        b"cli",
        b"command",
        b"flash_erase",
        b"dump",
    ]

    MSP_MARKERS = [
        b"MSP",
        b"mspProcess",
        b"mspCommand",
    ]

    def marker_exists(self, blob: bytes, markers):
        blob_lower = blob.lower()
        return any(marker.lower() in blob_lower for marker in markers)

    def analyze(self, blob: bytes):
        vector = self.marker_exists(blob, self.VECTOR_MARKERS)
        callback = self.marker_exists(blob, self.CALLBACK_MARKERS)
        cli = self.marker_exists(blob, self.CLI_MARKERS)
        msp = self.marker_exists(blob, self.MSP_MARKERS)

        hook_possible = vector or callback or cli or msp

        confidence = "LOW"
        if callback and (cli or msp):
            confidence = "HIGH"
        elif hook_possible:
            confidence = "MEDIUM"

        reasons = []

        if vector:
            reasons.append(
                "Interrupt and exception vector markers such as HardFault, SysTick, "
                "PendSV, Reset, or NMI are present, creating potential hook points "
                "for privileged control-flow interception."
            )

        if callback:
            reasons.append(
                "Scheduler callback, worker dispatch, or runtime function redirection "
                "surfaces were detected, which may allow stealth execution hijacking."
            )

        if cli:
            reasons.append(
                "CLI command dispatch surfaces are present and may be hookable for "
                "hidden diagnostic command interception or malicious command extension."
            )

        if msp:
            reasons.append(
                "MSP command processing surfaces were found, allowing possible hook-based "
                "interception of Betaflight control packets and telemetry commands."
            )

        if not reasons:
            reasons.append(
                "No strong dynamic dispatch or hookable execution surfaces were detected."
            )

        return SyscallHookResult(
            hook_possible=hook_possible,
            vector_table_exposed=vector,
            callback_dispatch_present=callback,
            cli_dispatch_present=cli,
            msp_dispatch_present=msp,
            confidence=confidence,
            reason=" ".join(reasons)
        )