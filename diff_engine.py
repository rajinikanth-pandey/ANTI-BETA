from pathlib import Path


class BinaryDiffEngine:
    def __init__(self, baseline_path: str, modified_path: str):
        self.baseline_path = Path(baseline_path)
        self.modified_path = Path(modified_path)

    def load_files(self):
        with open(self.baseline_path, "rb") as f:
            baseline = f.read()

        with open(self.modified_path, "rb") as f:
            modified = f.read()

        return baseline, modified

    def identify_region(self, offset):
        if offset < 0x10000:
            return "Bootloader / Startup Region"
        elif offset < 0x70000:
            return "Main Firmware Logic Region"
        elif offset < 0x7C000:
            return "Configuration / Metadata Region"
        return "Sensitive End Memory Region"

    def describe_change(self, before, after, offset):
        region = self.identify_region(offset)

        if after == 0x00:
            reason = (
                "This byte was overwritten with zero, which may indicate a wipe, "
                "partial erase, or intentional nullification of firmware logic."
            )
        elif after == 0xFF:
            reason = (
                "This byte changed to 0xFF, a common flash erased state. "
                "Large clusters of such changes may indicate firmware region erasure."
            )
        else:
            reason = (
                "This byte value was modified, suggesting firmware logic, metadata, "
                "or hidden payload changes in the selected memory region."
            )

        return f"{region}: {reason}"

    def diff_offsets(self):
        baseline, modified = self.load_files()

        if len(baseline) != len(modified):
            raise ValueError("Binary sizes do not match")

        changes = []

        for offset, (b1, b2) in enumerate(zip(baseline, modified)):
            if b1 != b2:
                changes.append({
                    "offset": hex(offset),
                    "before": hex(b1),
                    "after": hex(b2),
                    "region": self.identify_region(offset),
                    "description": self.describe_change(b1, b2, offset)
                })

        return changes

    def detect_mass_erase(self, threshold=128):
        changes = self.diff_offsets()

        suspicious_runs = []
        current_run = []

        for item in changes:
            if item["after"] in ["0x0", "0xff"]:
                current_run.append(item)
            else:
                if len(current_run) >= threshold:
                    suspicious_runs.append({
                        "length": len(current_run),
                        "start_offset": current_run[0]["offset"],
                        "end_offset": current_run[-1]["offset"],
                        "description": (
                            "A large continuous erased region was detected. "
                            "This may represent deliberate firmware wiping, stealth payload removal, "
                            "or anti-forensic evidence destruction."
                        )
                    })
                current_run = []

        return suspicious_runs

    def summarize_changes(self):
        changes = self.diff_offsets()
        baseline, _ = self.load_files()

        total = len(changes)
        percent = round((total / len(baseline)) * 100, 2)

        if total == 0:
            severity = "No suspicious modification detected"
            explanation = (
                "The firmware images are identical, suggesting no byte-level tampering."
            )
        elif percent < 1:
            severity = "Minor firmware modification"
            explanation = (
                "Only a very small number of bytes changed, which may represent "
                "normal configuration updates or metadata refreshes."
            )
        elif percent < 5:
            severity = "Moderate suspicious modification"
            explanation = (
                "A noticeable percentage of firmware bytes changed. "
                "This may indicate patching, stealth configuration tampering, "
                "or partial malicious logic insertion."
            )
        else:
            severity = "High-risk firmware tampering"
            explanation = (
                "A significant portion of the firmware was altered. "
                "This strongly suggests intentional code mutation, persistence implants, "
                "or anti-forensic payload injection."
            )

        return {
            "total_changes": total,
            "change_percent": percent,
            "severity": severity,
            "description": explanation
        }