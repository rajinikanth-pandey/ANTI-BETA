from dataclasses import dataclass


@dataclass
class FragmentationResult:
    fragmented: bool
    cluster_count: int
    average_gap: float
    confidence: str
    reason: str


class FragmentationDetector:
    def analyze(self, changes, cluster_window=64):
        offsets = sorted(int(c["offset"], 16) for c in changes)

        if not offsets:
            return FragmentationResult(
                fragmented=False,
                cluster_count=0,
                average_gap=0.0,
                confidence="LOW",
                reason=(
                    "No modified offsets were found in the firmware image. "
                    "This indicates either no tampering or a perfectly identical comparison."
                )
            )

        clusters = 1
        gaps = []
        cluster_start = offsets[0]

        for off in offsets[1:]:
            gap = off - cluster_start
            gaps.append(gap)

            if gap > cluster_window:
                clusters += 1
                cluster_start = off

        avg_gap = sum(gaps) / len(gaps) if gaps else 0.0
        fragmented = clusters > 4

        confidence = "LOW"
        if clusters > 8:
            confidence = "HIGH"
        elif fragmented:
            confidence = "MEDIUM"

        if fragmented:
            reason = (
                f"The modified bytes are distributed across {clusters} disconnected "
                f"memory clusters with an average inter-cluster gap of {avg_gap:.2f} bytes. "
                "This highly fragmented pattern is suspicious because stealth implants "
                "often scatter payload logic to avoid easy forensic detection."
            )
        else:
            reason = (
                f"The mutation pattern remains within {clusters} closely grouped regions "
                f"with an average gap of {avg_gap:.2f} bytes. "
                "This clustering behavior is more consistent with normal feature updates "
                "or localized configuration changes."
            )

        return FragmentationResult(
            fragmented=fragmented,
            cluster_count=clusters,
            average_gap=avg_gap,
            confidence=confidence,
            reason=reason
        )