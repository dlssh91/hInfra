"""실행 환경 모델 적합성 체커 — `python3 -m judge_tool.envcheck`.

로컬 Ollama LLM 판정(production 모델=qwen3-coder:30b, 다운로드 ~19GB / 실행
footprint ≈25GB @16K컨텍스트)을 돌리기 전에 "이 PC에서 어떤 모델을 쓸 수
있는지"를 미리 확인하는 전용 명령이다.

설계 결정(사용자 확정, 절대 준수):
1. 전용 명령만 — preflight(main.run 판정 경로)에 자동 통합하지 않는다.
2. RAM 중심 + GPU 베스트에포트 — 총 RAM을 fit 판정의 안전 기준선(budget)으로
   삼는다. GPU/VRAM은 감지되면 참고 정보로만 표시한다.
3. 추천만, 자동 전환 절대 금지 — 이 모듈은 모델을 바꾸지 않는다. 실행자가
   리포트를 보고 명시적으로 --model을 지정해야 한다(약한 모델 자동사용은
   거짓양호 위험 — 이 저장소 최우선 금기).

불변 계약: stdlib + 기존 requests만 사용(신규 의존성 금지). 기존 판정 코드
(main.run, judge.OllamaClient, preflight)는 무수정 — 이 모듈은 신규/격리.
크로스플랫폼이며 감지 실패 시에도 크래시하지 않는다(None/안내 문구로 폴백).
"""
import argparse
import ctypes
import os
import platform
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

import requests

from judge_tool.judge import _NUM_CTX

# production 모델 — 판정 품질이 이 모델 기준으로 보정되어 있다.
# 다운로드 크기는 미설치 시 footprint 추정용 근사치(Ollama 라이브러리 기준,
# qwen3-coder:30b Q4_K_M 근사 ~19GB) — 실제 값은 설치 후 /api/tags에서 확인된다.
PRODUCTION_MODEL = "qwen3-coder:30b"
PRODUCTION_DOWNLOAD_GB = 19.0


def detect_total_ram_gb() -> Optional[float]:
    """크로스플랫폼 총 물리 RAM(GB). 감지 실패 시 None(크래시 금지)."""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return (pages * page_size) / (1024 ** 3)
    except (ValueError, OSError, AttributeError):
        pass

    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5, check=True)
            return int(out.stdout.strip()) / (1024 ** 3)
        except (subprocess.SubprocessError, OSError, ValueError):
            pass

    if sys.platform.startswith("win"):
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ok = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            if ok:
                return stat.ullTotalPhys / (1024 ** 3)
        except (OSError, AttributeError, ValueError):
            pass

    return None


def detect_vram_gb() -> Tuple[Optional[float], str]:
    """VRAM 베스트에포트 감지. (vram_gb, source_note) 반환.

    실패해도 크래시하지 않는다 — (None, "none")으로 폴백.
    """
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.total",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5, check=True)
            first_line = out.stdout.strip().splitlines()[0].strip()
            return float(first_line) / 1024.0, "nvidia"
        except (subprocess.SubprocessError, OSError, ValueError, IndexError):
            return None, "none"

    if sys.platform == "darwin" and platform.machine() == "arm64":
        # Apple Silicon 통합메모리 — 별도 VRAM이 없고 RAM이 곧 예산이다.
        return None, "apple_unified"

    return None, "none"


def list_installed_models(
        ollama_url: str, timeout: int = 5) -> Tuple[List[dict], Optional[str]]:
    """GET {ollama_url}/api/tags 로 설치된 모델 목록을 조회한다.

    Ollama 미가동/오류 시 ([], "에러문자열")로 폴백한다(크래시 금지).
    judge.OllamaClient.health_check()가 쓰는 것과 동일한 엔드포인트를
    재사용하되, OllamaClient 인스턴스나 그 상태에는 관여하지 않는다.
    """
    try:
        resp = requests.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001 - 서버 미가동/네트워크 오류 등 원인 다양
        return [], f"Ollama 서버({ollama_url})에 연결할 수 없습니다: {type(e).__name__}: {e}"

    models = []
    for m in (data.get("models") or []):
        if not isinstance(m, dict):
            continue
        name = m.get("name", "")
        size_bytes = m.get("size", 0) or 0
        # RAM 감지(1024**3)와 동일 단위(GiB)로 통일 — footprint vs budget 비교
        # 일관성 확보(Opus 리뷰 Medium).
        models.append({"name": name, "size_gb": size_bytes / (1024 ** 3)})
    return models, None


def estimate_footprint_gb(download_size_gb: float, num_ctx: int) -> float:
    """모델 실행 시 메모리 footprint 러프 추정치(GB).

    러프 추정, Q4_K_M 기준 경험칙(출처: Ollama VRAM 공식 —
    https://github.com/ollama/ollama 커뮤니티 가이드 근사치).
    footprint ≈ download_size*1.2(가중치+KV캐시 오버헤드)
                + (num_ctx/4096)*0.5(컨텍스트 확장분)
                + 0.5(런타임 자체 오버헤드).
    """
    return download_size_gb * 1.2 + (num_ctx / 4096) * 0.5 + 0.5


def fit_verdict(footprint_gb: float, budget_gb: float) -> str:
    """footprint 대비 budget(보통 총 RAM)의 적합도 판정.

    OS·타 애플리케이션 여유분 확보를 위해 budget 전량을 쓰지 않는다.
    """
    if budget_gb <= 0:
        return "불가"
    ratio_budget_80 = budget_gb * 0.8
    ratio_budget_95 = budget_gb * 0.95
    if footprint_gb <= ratio_budget_80:
        return "여유"
    if footprint_gb <= ratio_budget_95:
        return "빠듯"
    return "불가"


def build_report(ollama_url: str, model: str, num_ctx: int) -> dict:
    """RAM/VRAM/설치모델/production fit/추천을 조합한 리포트 dict를 만든다."""
    ram_gb = detect_total_ram_gb()
    vram_gb, vram_source = detect_vram_gb()
    budget_gb = ram_gb if ram_gb is not None else 0.0

    installed_raw, ollama_error = list_installed_models(ollama_url)

    installed = []
    for m in installed_raw:
        footprint = estimate_footprint_gb(m["size_gb"], num_ctx)
        verdict = fit_verdict(footprint, budget_gb) if ram_gb is not None else "판정불가(RAM 미감지)"
        installed.append({
            "name": m["name"],
            "size_gb": m["size_gb"],
            "footprint_gb": footprint,
            "verdict": verdict,
        })

    # production 모델 fit — 설치돼 있으면 실제 크기, 아니면 상수로 추정.
    # ⚠️ exact match만 — base-name(':' 앞) 매칭은 같은 계열 '다른 크기 태그'
    # (예: qwen3-coder:7b)를 30b로 오인해 미설치 모델을 "설치·여유"로 오판하는
    # 거짓양호형 버그를 낳는다(Opus 리뷰 High). 반드시 태그까지 정확히 일치해야 한다.
    prod_entry = next((e for e in installed if e["name"] == model), None)
    if prod_entry is not None:
        prod_footprint = prod_entry["footprint_gb"]
        prod_installed = True
    else:
        prod_footprint = estimate_footprint_gb(PRODUCTION_DOWNLOAD_GB, num_ctx)
        prod_installed = False
    prod_verdict = fit_verdict(prod_footprint, budget_gb) if ram_gb is not None else "판정불가(RAM 미감지)"

    # 추천 — fit != "불가"인 설치 모델 중 가장 큰(footprint 기준) 것.
    fittable = [e for e in installed if e["verdict"] not in ("불가", "판정불가(RAM 미감지)")]
    recommendation = None
    if fittable:
        recommendation = max(fittable, key=lambda e: e["footprint_gb"])["name"]

    report = {
        "ram_gb": ram_gb,
        "vram_gb": vram_gb,
        "vram_source": vram_source,
        "budget_gb": budget_gb,
        "installed": installed,
        "production_fit": {
            "model": model,
            "installed": prod_installed,
            "footprint_gb": prod_footprint,
            "verdict": prod_verdict,
        },
        "recommendation": recommendation,
    }
    if ollama_error:
        report["ollama_error"] = ollama_error
    return report


def format_report(report: dict) -> str:
    """사람이 읽는 한국어 리포트 문자열을 만든다."""
    lines = []
    lines.append("=" * 64)
    lines.append("judge_tool 실행 환경 모델 적합성 리포트")
    lines.append("=" * 64)

    ram_gb = report.get("ram_gb")
    if ram_gb is not None:
        lines.append(f"총 RAM        : {ram_gb:.1f} GB (fit 판정 기준선)")
    else:
        lines.append("총 RAM        : 감지 실패 (알 수 없음) — fit 판정 불가")

    vram_gb = report.get("vram_gb")
    vram_source = report.get("vram_source", "none")
    if vram_gb is not None:
        lines.append(f"VRAM (참고)   : {vram_gb:.1f} GB (source={vram_source})")
    elif vram_source == "apple_unified":
        lines.append("VRAM (참고)   : 없음 — Apple Silicon 통합메모리(RAM이 곧 예산, source=apple_unified)")
    else:
        lines.append("VRAM (참고)   : 감지 안 됨 (source=none)")

    lines.append("")

    if report.get("ollama_error"):
        lines.append(f"[안내] {report['ollama_error']}")
        lines.append("Ollama 서버가 켜져 있는지 확인 후 다시 실행하세요.")
        lines.append("")

    installed = report.get("installed", [])
    lines.append("설치된 모델 목록:")
    if not installed:
        lines.append("  (설치된 모델 없음, 또는 Ollama 미가동)")
    else:
        lines.append(f"  {'이름':<28}{'크기(GB)':>10}{'footprint(GB)':>16}  판정")
        for e in installed:
            lines.append(
                f"  {e['name']:<28}{e['size_gb']:>10.1f}"
                f"{e['footprint_gb']:>16.1f}  {e['verdict']}")
    lines.append("")

    pf = report["production_fit"]
    tag = "" if pf["installed"] else " (미설치, 추정)"
    lines.append(
        f"production 모델 {pf['model']}{tag}: "
        f"footprint≈{pf['footprint_gb']:.1f}GB → 판정: {pf['verdict']}")
    lines.append("")

    rec = report.get("recommendation")
    if rec:
        lines.append(f"추천 모델(이 PC에서 실행 가능한 것 중 가장 큰 것): {rec}")
    else:
        lines.append("추천 모델: 없음 (fit 가능한 설치 모델이 없습니다)")
    lines.append("")

    lines.append(
        "[경고] 판정 품질은 qwen3-coder:30b 기준으로 보정되어 있습니다. "
        "더 작은 모델은 프록시일 뿐 품질이 보증되지 않습니다. "
        "이 도구는 모델을 자동 전환하지 않으니, 실제 판정 실행 시 "
        "--model 로 사용할 모델을 직접 명시하세요.")
    lines.append("=" * 64)
    return "\n".join(lines)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        prog="python3 -m judge_tool.envcheck",
        description="실행 환경(RAM/VRAM/설치 모델) 대비 Ollama 모델 적합성 체커. "
                     "추천만 하며 자동 전환하지 않습니다.")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--model", default=PRODUCTION_MODEL,
                    help=f"적합성을 확인할 production 모델(기본 {PRODUCTION_MODEL})")
    ap.add_argument("--num-ctx", type=int, default=_NUM_CTX,
                    help=f"footprint 추정에 쓸 컨텍스트 길이(기본 {_NUM_CTX}, "
                         "judge.py 판정 경로와 동일)")
    args = ap.parse_args(argv)

    report = build_report(args.ollama_url, args.model, args.num_ctx)
    print(format_report(report))


if __name__ == "__main__":
    main()
