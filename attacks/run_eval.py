"""Run the labeled payload corpus through InjectionDetector and report
precision/recall/F1 plus a false-positive breakdown.

  python -m attacks.run_eval                 # heuristic layer only, no API calls
  python -m attacks.run_eval --llm-judge      # full two-layer detector (costs a few cents)
"""

from __future__ import annotations

import argparse

from gateway.detector import InjectionDetector
from attacks.payloads import CASES


def run(use_llm_judge: bool) -> None:
    detector = InjectionDetector(use_llm_judge=use_llm_judge)

    tp = fp = tn = fn = 0
    false_positives = []
    false_negatives = []

    for text, is_attack, _category in CASES:
        result = detector.scan(text)
        predicted = result.matched
        if is_attack and predicted:
            tp += 1
        elif is_attack and not predicted:
            fn += 1
            false_negatives.append(text)
        elif not is_attack and predicted:
            fp += 1
            false_positives.append((text, result.category, result.source.value))
        else:
            tn += 1

    total = len(CASES)
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else float("nan")

    mode = "heuristic + LLM judge" if use_llm_judge else "heuristic only"
    print(f"Detector mode: {mode}")
    print(f"Cases: {total} ({sum(1 for _, a, _ in CASES if a)} attacks, {sum(1 for _, a, _ in CASES if not a)} benign)")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={precision:.2f}  Recall={recall:.2f}  F1={f1:.2f}")

    if false_positives:
        print("\nFalse positives:")
        for text, category, source in false_positives:
            print(f"  - [{source}/{category}] {text!r}")

    if false_negatives:
        print("\nFalse negatives:")
        for text in false_negatives:
            print(f"  - {text!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm-judge", action="store_true", help="also run the LLM-judge layer (requires ANTHROPIC_API_KEY)")
    args = parser.parse_args()
    run(use_llm_judge=args.llm_judge)
