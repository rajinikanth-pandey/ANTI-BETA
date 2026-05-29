from dataclasses import dataclass


@dataclass
class RootkitPatternResult:
    rootkit_persistence_possible: bool
    callback_shadowing_surface: bool
    task_name_masquerade_surface: bool
    vector_redirection_surface: bool
    hidden_region_surface: bool
    confidence: str
    reason: str


class RootkitPatternDetector:
    CALLBACK_MARKERS = [
        b"callback",
        b"worker",
        b"scheduler",
        b"dispatch",
        b"blx",
    ]

    TASK_MARKERS = [
        b"CLI",
        b"MSP",
        b"BLACKBOX",
        b"GYRO",
        b"OSD",
        b"TASK",
    ]

    VECTOR_MARKERS = [
        b"Reset",
        b"SysTick",
        b"HardFault",
        b"PendSV",
    ]

    HIDDEN_REGION_MARKERS = [
        b"backup",
        b"shadow",
        b"profile",
        b"flashfs",
        b"blackbox",
    ]

    def marker_exists(self, blob: bytes, markers):
        blob_lower = blob.lower()
        return any(marker.lower() in blob_lower for marker in markers)

    def analyze(self, blob: bytes):
        callback = self.marker_exists(blob, self.CALLBACK_MARKERS)
        task = self.marker_exists(blob, self.TASK_MARKERS)
        vector = self.marker_exists(blob, self.VECTOR_MARKERS)
        hidden = self.marker_exists(blob, self.HIDDEN_REGION_MARKERS)

        possible = callback or vector or hidden

        confidence = "LOW"
        if callback and vector and hidden:
            confidence = "HIGH"
        elif possible:
            confidence = "MEDIUM"

        reasons = []

        if callback:
            reasons.append(
                "Scheduler callback or worker dispatch surfaces were found, which may allow "
                "malicious logic to persist by hijacking normal runtime execution paths."
            )

        if task:
            reasons.append(
                "Trusted task names such as CLI, MSP, GYRO, OSD, or BLACKBOX are present, "
                "creating opportunities for rootkit code to hide as legitimate Betaflight tasks."
            )

        if vector:
            reasons.append(
                "Interrupt or exception vector markers such as Reset, SysTick, HardFault, "
                "or PendSV suggest possible control-flow redirection during privileged execution."
            )

        if hidden:
            reasons.append(
                "Hidden persistence surfaces such as shadow, backup, profile, flashfs, "
                "or blackbox regions may be used to store stealth payload state."
            )

        if not reasons:
            reasons.append(
                "No strong rootkit-style persistence surfaces were detected in the firmware."
            )

        return RootkitPatternResult(
            rootkit_persistence_possible=possible,
            callback_shadowing_surface=callback,
            task_name_masquerade_surface=task,
            vector_redirection_surface=vector,
            hidden_region_surface=hidden,
            confidence=confidence,
            reason=" ".join(reasons)
        )