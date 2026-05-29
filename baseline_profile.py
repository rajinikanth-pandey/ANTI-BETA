import json
from pathlib import Path
from datetime import datetime


class BaselineProfile:
    def __init__(self, profile_path="samples/normal_profile.json"):
        self.profile_path = Path(profile_path)

    def save_profile(self, changes):
        offsets = [c["offset"] for c in changes]

        profile = {
            "normal_offsets": offsets,
            "normal_change_count": len(changes),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "description": (
                "This profile stores the trusted baseline pattern of normal firmware "
                "offset mutations. Future scans use this as a reference to detect "
                "stealth deviations, hidden persistence, or abnormal mutation drift."
            )
        }

        self.profile_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.profile_path, "w") as f:
            json.dump(profile, f, indent=4)

    def load_profile(self):
        if not self.profile_path.exists():
            return None

        try:
            with open(self.profile_path, "r") as f:
                profile = json.load(f)

            profile.setdefault(
                "description",
                "Trusted firmware baseline profile for stealth deviation detection."
            )

            return profile

        except json.JSONDecodeError:
            return None