import pytest
from app.models.schemas import (
    VerdictEnum,
    ClamAVResult,
    MLInferenceResult,
    PEAnalysisResult,
    PEHeaderInfo,
)

def create_mock_pe_analysis(entropy: float = 6.2, suspicious_count: int = 0) -> PEAnalysisResult:
    headers = PEHeaderInfo(
        machine="AMD64",
        machine_hex="0x8664",
        number_of_sections=4,
        time_date_stamp=1600000000,
        characteristics_hex="0x0022",
        is_dll=False,
        is_executable_image=True,
        subsystem="WINDOWS_GUI",
        magic="PE32+ (64-bit)",
        entry_point_rva="0x00001000",
        image_base="0x140000000"
    )
    return PEAnalysisResult(
        status="success",
        headers=headers,
        sections=[],
        imported_dlls_count=5,
        imported_dlls=[],
        total_imports_count=20,
        exported_functions_count=0,
        exported_functions=[],
        file_entropy=entropy,
        suspicious_indicators=["MockAPI"] if suspicious_count > 0 else []
    )

def synthesize_verdict(clamav_res: ClamAVResult, ml_res: MLInferenceResult, pe_analysis: PEAnalysisResult):
    """Replicates the conservative verdict synthesis logic from scans endpoint."""
    verdict_reasons = []
    if clamav_res.matched:
        verdict = VerdictEnum.MALICIOUS
        verdict_reasons.append(f"Confirmed malware signature match: {clamav_res.signature_name}")
    elif ml_res.available and ml_res.prediction == "malicious" and (ml_res.confidence_score or 0) >= 0.75:
        verdict = VerdictEnum.SUSPICIOUS
        verdict_reasons.append("ML flagged suspicious structural anomalies")
    elif len(pe_analysis.suspicious_indicators) >= 2 and pe_analysis.file_entropy > 7.3:
        verdict = VerdictEnum.SUSPICIOUS
        verdict_reasons.append("High entropy and sensitive API injection imports.")
    elif clamav_res.available and clamav_res.status == "clean" and ml_res.available and ml_res.prediction == "benign":
        if clamav_res.is_emulator:
            verdict = VerdictEnum.INCONCLUSIVE
            verdict_reasons.append("ML model classified file as benign, but ClamAV signature scan used the development-only EICAR emulator rather than the official production ClamAV database.")
        else:
            verdict = VerdictEnum.NO_THREAT_DETECTED
            verdict_reasons.append("All scans completed without threat indicators.")
    else:
        verdict = VerdictEnum.INCONCLUSIVE
        if not clamav_res.available:
            verdict_reasons.append("ClamAV signature engine was unavailable during this scan.")
        if not ml_res.available:
            verdict_reasons.append("Random Forest ML model is not loaded.")
        verdict_reasons.append("Inconclusive threat verdict because engines are offline.")
    return verdict, verdict_reasons

def test_verdict_inconclusive_when_clamav_and_ml_unavailable():
    clamav = ClamAVResult(status="unavailable", available=False, matched=False, message="Offline")
    ml = MLInferenceResult(status="model_not_loaded", available=False, model_name="RF", message="Not loaded")
    pe = create_mock_pe_analysis()
    
    verdict, reasons = synthesize_verdict(clamav, ml, pe)
    assert verdict == VerdictEnum.INCONCLUSIVE
    assert verdict != VerdictEnum.NO_THREAT_DETECTED

def test_verdict_inconclusive_when_clamav_clean_but_ml_unavailable():
    clamav = ClamAVResult(status="clean", available=True, matched=False, message="Clean")
    ml = MLInferenceResult(status="model_not_loaded", available=False, model_name="RF", message="Not loaded")
    pe = create_mock_pe_analysis()
    
    verdict, reasons = synthesize_verdict(clamav, ml, pe)
    # MUST be INCONCLUSIVE because ML is not available
    assert verdict == VerdictEnum.INCONCLUSIVE
    assert verdict != VerdictEnum.NO_THREAT_DETECTED

def test_verdict_inconclusive_when_ml_benign_but_clamav_unavailable():
    clamav = ClamAVResult(status="unavailable", available=False, matched=False, message="Offline")
    ml = MLInferenceResult(status="loaded", available=True, model_name="RF", prediction="benign", confidence_score=0.92, message="Benign")
    pe = create_mock_pe_analysis()
    
    verdict, reasons = synthesize_verdict(clamav, ml, pe)
    # MUST be INCONCLUSIVE because ClamAV is offline
    assert verdict == VerdictEnum.INCONCLUSIVE
    assert verdict != VerdictEnum.NO_THREAT_DETECTED

def test_verdict_malicious_when_clamav_matches_even_if_ml_offline():
    clamav = ClamAVResult(status="infected", available=True, matched=True, signature_name="Win.Trojan.Generic", message="Infected")
    ml = MLInferenceResult(status="model_not_loaded", available=False, model_name="RF", message="Not loaded")
    pe = create_mock_pe_analysis()
    
    verdict, reasons = synthesize_verdict(clamav, ml, pe)
    assert verdict == VerdictEnum.MALICIOUS
    assert "Win.Trojan.Generic" in reasons[0]

def test_verdict_clean_only_when_both_clamav_and_ml_confirm_benign():
    clamav = ClamAVResult(status="clean", available=True, matched=False, is_emulator=False, message="Clean")
    ml = MLInferenceResult(status="loaded", available=True, model_name="RF", prediction="benign", confidence_score=0.95, message="Benign")
    pe = create_mock_pe_analysis()
    
    verdict, reasons = synthesize_verdict(clamav, ml, pe)
    assert verdict == VerdictEnum.NO_THREAT_DETECTED

def test_verdict_emulator_never_returns_no_threat_detected():
    clamav = ClamAVResult(status="clean", available=True, matched=False, is_emulator=True, message="Clean test emulator")
    ml = MLInferenceResult(status="loaded", available=True, model_name="RF", prediction="benign", confidence_score=0.95, message="Benign")
    pe = create_mock_pe_analysis()
    
    verdict, reasons = synthesize_verdict(clamav, ml, pe)
    assert verdict == VerdictEnum.INCONCLUSIVE
    assert verdict != VerdictEnum.NO_THREAT_DETECTED
    assert "emulator" in reasons[0].lower()

