"""Run a labeled payload corpus through InjectionDetector and report
precision/recall/F1 plus a false-positive breakdown.

  python -m attacks.run_eval                      # English corpus, heuristic only, no API calls
  python -m attacks.run_eval --lang zh            # Chinese parallel corpus
  python -m attacks.run_eval --lang all           # both, with a side-by-side comparison
  python -m attacks.run_eval --llm-judge          # full two-layer detector (costs a few cents)
  python -m attacks.run_eval --lang all --llm-judge   # the cross-language x cross-layer matrix

The --lang all view is the interesting one: because payloads_zh.py is a faithful
parallel of payloads.py (same intent, same category, same order), any gap between
the two columns isolates the effect of language on detection.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

from gateway.detector import InjectionDetector
from attacks.payloads import CASES as CASES_EN
from attacks.payloads_zh import CASES as CASES_ZH
from attacks.payloads_zh_heldout import CASES as CASES_ZH_HELDOUT

# zh-heldout is scored separately from zh on purpose: the Chinese heuristics were
# written against zh, so its score measures fit. zh-heldout was written afterwards
# and is the only one of the two that says anything about generalization.
CORPORA = {"en": CASES_EN, "zh": CASES_ZH, "zh-heldout": CASES_ZH_HELDOUT}


@dataclass
class Scores:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    false_positives: list = None
    false_negatives: list = None

    def __post_init__(self):
        if self.false_positives is None:
            self.false_positives = []
        if self.false_negatives is None:
            self.false_negatives = []

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else float("nan")

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else float("nan")

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else float("nan")


def score_corpus(detector: InjectionDetector, cases) -> Scores:
    s = Scores()
    for text, is_attack, _category in cases:
        result = detector.scan(text)
        predicted = result.matched
        if is_attack and predicted:
            s.tp += 1
        elif is_attack and not predicted:
            s.fn += 1
            s.false_negatives.append(text)
        elif not is_attack and predicted:
            s.fp += 1
            s.false_positives.append((text, result.category, result.source.value))
        else:
            s.tn += 1
    return s


def report_one(lang: str, cases, s: Scores) -> None:
    print(f"\n--- {lang.upper()} ---")
    print(f"Cases: {len(cases)} ({sum(1 for _, a, _ in cases if a)} attacks, "
          f"{sum(1 for _, a, _ in cases if not a)} benign)")
    print(f"TP={s.tp} FP={s.fp} TN={s.tn} FN={s.fn}")
    print(f"Precision={s.precision:.2f}  Recall={s.recall:.2f}  F1={s.f1:.2f}")

    if s.false_positives:
        print("False positives:")
        for text, category, source in s.false_positives:
            print(f"  - [{source}/{category}] {text}")
    if s.false_negatives:
        print("False negatives:")
        for text in s.false_negatives:
            print(f"  - {text}")


def report_comparison(results: dict[str, Scores]) -> None:
    print("\n=== Cross-language comparison ===")
    width = max(12, max(len(l) for l in results) + 2)
    header = f"{'metric':<12}" + "".join(f"{l.upper():>{width}}" for l in results)
    print(header)
    print("-" * len(header))
    for name in ("recall", "precision", "f1"):
        row = f"{name:<12}"
        for s in results.values():
            row += f"{getattr(s, name):>{width}.2f}"
        print(row)
    row = f"{'missed':<12}"
    for s in results.values():
        row += f"{s.fn:>{width}}"
    print(row + "   <- attacks not detected")


def run(use_llm_judge: bool, langs: list[str]) -> None:
    detector = InjectionDetector(use_llm_judge=use_llm_judge)
    mode = "heuristic + LLM judge" if use_llm_judge else "heuristic only"
    print(f"Detector mode: {mode}")
    if use_llm_judge:
        print(f"Judge model:   {detector.judge_model}")

    results: dict[str, Scores] = {}
    for lang in langs:
        cases = CORPORA[lang]
        results[lang] = score_corpus(detector, cases)
        report_one(lang, cases, results[lang])

    if len(results) > 1:
        report_comparison(results)

    # A judge call that fails degrades to the heuristic verdict, which silently
    # turns a two-layer run into a one-layer run while still printing two-layer
    # numbers. Refuse to let that pass unremarked: the scores above are not
    # measurements of the two-layer detector if this count is non-zero.
    if use_llm_judge and detector.judge_errors:
        total = sum(len(CORPORA[l]) for l in langs)
        print(f"\n{'!' * 68}")
        print(f"WARNING: {detector.judge_errors} judge call(s) failed out of ~{total} cases.")
        print("Those cases fell back to the heuristic verdict, so the scores above")
        print("UNDERSTATE the judge and do not describe a working two-layer detector.")
        print(f"Last error: {detector.last_judge_error}")
        print("If this is rate limiting, raise GATEWAY_JUDGE_BACKOFF and re-run.")
        print(f"{'!' * 68}")
    elif use_llm_judge:
        print("\nAll judge calls completed; two-layer scores are valid.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm-judge", action="store_true",
                        help="also run the LLM-judge layer (requires a provider API key)")
    parser.add_argument("--lang", default="en", choices=["en", "zh", "zh-heldout", "all"],
                        help="which corpus to evaluate (default: en)")
    args = parser.parse_args()
    langs = ["en", "zh", "zh-heldout"] if args.lang == "all" else [args.lang]
    run(use_llm_judge=args.llm_judge, langs=langs)
