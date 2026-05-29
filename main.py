from diff_engine import BinaryDiffEngine
from heuristics import HeuristicAnalyzer
from rollback_detector import RollbackHardeningTester
from covert_channel_detector import CovertChannelDetector
from stealth_region_detector import StealthRegionDetector
from baseline_profile import BaselineProfile
from syscall_hook_detector import SyscallHookDetector
from rootkit_detector import RootkitPatternDetector
from fragmentation_detector import FragmentationDetector
from masquerade_detector import MasqueradeDetector
from secure_boot_bypass_detector import SecureBootBypassDetector
from integrity_bypass_detector import IntegrityBypassDetector
from report_generator import PDFReportGenerator


def confidence_to_score(level: str) -> int:
    mapping = {
        "LOW": 35,
        "MEDIUM": 70,
        "HIGH": 95
    }
    return mapping.get(level, 50)


def run_analysis(original_path, modified_path):
    engine = BinaryDiffEngine(original_path, modified_path)
    changes = engine.diff_offsets()

    heuristic = HeuristicAnalyzer(changes)

    rollback = RollbackHardeningTester()
    covert = CovertChannelDetector()
    hook = SyscallHookDetector()
    rootkit = RootkitPatternDetector()
    fragment = FragmentationDetector()
    masquerade = MasqueradeDetector()
    secure_boot = SecureBootBypassDetector()
    integrity = IntegrityBypassDetector()

    profiler = BaselineProfile()
    profile = profiler.load_profile()

    if profile is None:
        profiler.save_profile(changes)
        profile = profiler.load_profile()

    stealth = StealthRegionDetector()
    stealth_result = stealth.analyze(profile["normal_offsets"], changes)

    with open(modified_path, "rb") as f:
        blob = f.read()

    rollback_result = rollback.analyze(blob)
    covert_result = covert.analyze(blob)
    hook_result = hook.analyze(blob)
    rootkit_result = rootkit.analyze(blob)
    fragment_result = fragment.analyze(changes)
    masquerade_result = masquerade.analyze(blob)
    secure_boot_result = secure_boot.analyze(blob)
    integrity_result = integrity.analyze(blob)

    # cache reusable results
    mass_erase_regions = len(engine.detect_mass_erase())
    volume = heuristic.classify_change_volume()
    ff_pattern = heuristic.detect_ff_fill()
    cluster_analysis = heuristic.detect_offset_clusters()
    region_analysis = heuristic.detect_sensitive_region_touch()

    module_confidence = {
        "rollback": confidence_to_score(rollback_result.confidence),
        "covert": confidence_to_score(covert_result.confidence),
        "stealth": confidence_to_score(stealth_result.confidence),
        "hook": confidence_to_score(hook_result.confidence),
        "rootkit": confidence_to_score(rootkit_result.confidence),
        "fragmentation": confidence_to_score(fragment_result.confidence),
        "masquerade": confidence_to_score(masquerade_result.confidence),
        "secure_boot": confidence_to_score(secure_boot_result.confidence),
        "integrity": confidence_to_score(integrity_result.confidence),
    }

    overall_score = sum(module_confidence.values()) // len(module_confidence)

    results = {
        "summary": engine.summarize_changes(),
        "total_changes": len(changes),
        "mass_erase_regions": mass_erase_regions,
        "volume": volume,
        "ff_pattern": ff_pattern,
        "cluster_analysis": cluster_analysis,
        "region_analysis": region_analysis,

        "rollback": rollback_result.__dict__,
        "covert": covert_result.__dict__,
        "stealth": stealth_result.__dict__,
        "hook": hook_result.__dict__,
        "rootkit": rootkit_result.__dict__,
        "fragmentation": fragment_result.__dict__,
        "masquerade": masquerade_result.__dict__,
        "secure_boot": secure_boot_result.__dict__,
        "integrity": integrity_result.__dict__,

        "visuals": {
            "overall_score": overall_score,
            "risk_distribution": {
                "rollback": module_confidence["rollback"],
                "covert": module_confidence["covert"],
                "rootkit": module_confidence["rootkit"],
                "secure_boot": module_confidence["secure_boot"],
                "integrity": module_confidence["integrity"],
            },
            "mutation_overview": {
                "total_changes": len(changes),
                "mass_erase_regions": mass_erase_regions,
                "stealth_deviation": stealth_result.deviation_count,
                "fragment_clusters": fragment_result.cluster_count
            },
            "module_confidence": module_confidence,
            "heuristic_metrics": {
                "change_volume": len(changes),
                "ff_fill_score": 100 if ff_pattern == "POSSIBLE_ERASE_TO_FF" else 25,
                "cluster_score": fragment_result.cluster_count * 10,
                "region_touch_score": 90 if region_analysis == "CONFIG_REGION_TOUCHED" else 20
            }
        }
    }

    try:
        pdf_bytes = PDFReportGenerator().build_pdf(results)
        results["pdf_report"] = pdf_bytes
    except Exception:
        results["pdf_report"] = None

    return results