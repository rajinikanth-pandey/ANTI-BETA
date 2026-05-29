class HeuristicAnalyzer:
    def __init__(self, changes):
        self.changes = changes

    def classify_change_volume(self):
        count = len(self.changes)

        if count <= 32:
            return {
                "status": "NORMAL_CONFIG_WRITE",
                "description": (
                    "Only a small number of bytes changed. "
                    "This usually indicates safe configuration updates, PID tuning, "
                    "metadata refreshes, or parameter changes."
                )
            }

        elif count <= 512:
            return {
                "status": "LARGE_CONFIG_OR_METADATA_UPDATE",
                "description": (
                    "A moderate number of bytes changed, which may represent "
                    "larger configuration writes, metadata updates, or partial "
                    "feature changes in the firmware."
                )
            }

        elif count <= 4096:
            return {
                "status": "SUSPICIOUS_BLOCK_MUTATION",
                "description": (
                    "A large block of firmware was modified. "
                    "This may indicate stealth payload insertion, hidden feature patching, "
                    "or suspicious runtime logic replacement."
                )
            }

        return {
            "status": "POTENTIAL_MASS_ERASE",
            "description": (
                "A very high number of bytes changed, strongly suggesting "
                "mass erase activity, destructive tampering, or anti-forensic wiping."
            )
        }

    def detect_ff_fill(self):
        ff_count = sum(
            1 for c in self.changes
            if c["after"] == "0xff"
        )

        if ff_count > 64:
            return {
                "status": "POSSIBLE_ERASE_TO_FF",
                "description": (
                    "A large number of bytes were changed to 0xFF, which is the "
                    "common erased state of flash memory. This strongly suggests "
                    "region wiping or stealth evidence removal."
                )
            }

        return {
            "status": "NO_FF_ERASE_PATTERN",
            "description": (
                "No strong flash erase signature was found. "
                "The mutation pattern appears more logic-based than erase-based."
            )
        }

    def detect_offset_clusters(self, cluster_window=64):
        offsets = [int(c["offset"], 16) for c in self.changes]

        if not offsets:
            return {
                "status": "NO_CHANGES",
                "description": "No modified offsets were detected in the firmware."
            }

        offsets.sort()

        clusters = 1
        start = offsets[0]

        for off in offsets[1:]:
            if off - start > cluster_window:
                clusters += 1
                start = off

        if clusters == 1:
            return {
                "status": "LOCALIZED_SINGLE_CLUSTER",
                "description": (
                    "All mutations are concentrated in one localized memory area. "
                    "This may indicate a focused patch or isolated configuration write."
                )
            }

        elif clusters <= 4:
            return {
                "status": "MULTI_CLUSTER_UPDATE",
                "description": (
                    "Changes are distributed across a few distinct regions. "
                    "This pattern may represent structured firmware feature updates "
                    "or staged malicious implants."
                )
            }

        return {
            "status": "HIGHLY_FRAGMENTED_MUTATION",
            "description": (
                "Mutations are scattered across many disconnected memory regions. "
                "This highly fragmented behavior is suspicious and often linked to "
                "stealth payload distribution."
            )
        }

    def detect_sensitive_region_touch(self):
        offsets = [int(c["offset"], 16) for c in self.changes]

        config_region = range(0x7C000, 0x7FFFF)

        for off in offsets:
            if off in config_region:
                return {
                    "status": "CONFIG_REGION_TOUCHED",
                    "description": (
                        "The modified bytes extend into the sensitive configuration "
                        "or metadata zone, which may affect calibration, boot flags, "
                        "or protected system parameters."
                    )
                }

        return {
            "status": "NON_CONFIG_REGION",
            "description": (
                "Sensitive configuration regions remain untouched. "
                "The detected changes are likely limited to executable logic regions."
            )
        }