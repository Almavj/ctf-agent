#!/usr/bin/env python3
"""CTF Agent - universal autonomous flag capture engine.

Handles ANY CTF challenge type: binary exploitation, reverse engineering,
forensics, cryptography, web, steganography, network analysis, misc.

Give it a file, IP, URL, or directory and it figures out what to do.
Runs locally with full system access.
"""

import argparse
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

from classifier import Classifier, ChallengeType, Classification
from planner import Planner
from executor import Executor
from memory import Memory, Step, Flag
from flag_parser import FlagParser


BANNER = r"""
   _____ _______ ______   ______ _             _____  ______ _           _
  / ____|__   __|  ____| |  ____| |           |  __ \|  ____(_)         | |
 | |       | |  | |__    | |__  | | __ _  __ _| |__) | |__   _ _ __   __| | ___ _ __
 | |       | |  |  __|   |  __| | |/ _` |/ _` |  ___/|  __| | | '_ \ / _` |/ _ \ '__|
 | |____   | |  | |      | |    | | (_| | (_| | |    | |    | | | | | (_| |  __/ |
  \_____|  |_|  |_|      |_|    |_|\__,_|\__, |_|    |_|    |_|_| |_|\__,_|\___|_|
                                          __/ |
                                         |___/   v3.0 - Universal CTF Solver
"""


class Agent:
    def __init__(self, args):
        self.target = args.target
        self.state_dir = args.state_dir
        self.max_steps = args.max_steps
        self.step_timeout = args.step_timeout

        self.memory = Memory(state_dir=self.state_dir)
        self.executor = Executor(timeout=self.step_timeout)
        self.planner = Planner(
            ollama_url=args.ollama_url,
            model=args.model,
        )
        self.flags = FlagParser()
        self.classifier = Classifier()

        self.challenge_info: Classification = None
        self.step_count = 0
        self.start_time = 0

    def run(self):
        print(BANNER)

        print(f"[*] Target:   {self.target}")
        print(f"[*] LLM:      {self.planner.ollama_url} ({self.planner.model})")
        print(f"[*] Max steps: {self.max_steps}")
        print()

        self._preflight()
        self._classify_target()
        self._initial_recon()
        self.planner.available_tools = self.executor.available_tools_list()
        print(f"[*] Available tools: {', '.join(self.planner.available_tools[:15])}...")
        print()

        self.start_time = time.time()

        for step_num in range(1, self.max_steps + 1):
            self.step_count = step_num
            if not self._step(step_num):
                break

        self._finish()

    def _preflight(self):
        print("[*] Pre-flight checks...")
        if not self.planner.check_ollama():
            print(f"[!] Cannot reach Ollama at {self.planner.ollama_url}")
            print("[!] Start with: ollama serve")
            sys.exit(1)
        print("[+] Ollama is running")

        if os.path.isfile(self.target):
            print(f"[+] Target file exists: {self.target}")
            size = os.path.getsize(self.target)
            print(f"    Size: {size:,} bytes")
        elif os.path.isdir(self.target):
            count = sum(len(f) for _, _, f in os.walk(self.target))
            print(f"[+] Target directory: {count} files")
        else:
            print(f"[+] Target: {self.target}")
        print()

    def _classify_target(self):
        print("[*] Classifying challenge...")
        self.challenge_info = self.classifier.classify_input(self.target)
        print(self.challenge_info.summary())
        print()

        self.memory.update_info("input", self.target)
        self.memory.update_info("challenge_type", self.challenge_info.challenge_type.value)
        self.memory.update_info("file_type", self.challenge_info.file_type)

    def _initial_recon(self):
        print("[*] Initial reconnaissance...")
        ct = self.challenge_info.challenge_type
        filepath = self.target

        if ct in (ChallengeType.BINARY, ChallengeType.REVERSE, ChallengeType.PWN):
            if os.path.isfile(filepath):
                print("  [*] Analyzing binary...")
                result = self.executor.binary.analyze(filepath)
                print(f"      {result.output[:500]}")
                self.memory.update_info("analysis", result.output[:1000])

                print("  [*] Extracting strings...")
                strings = self.executor.sys.strings(filepath, minlength=6)
                if strings.success:
                    interesting = [l for l in strings.output.split("\n")
                                   if any(k in l.lower() for k in [
                                       "flag", "ctf", "pass", "key", "secret",
                                       "admin", "root", "/bin/", "libc"
                                   ])]
                    if interesting:
                        self.memory.update_info("interesting_strings", interesting[:20])
                        print(f"      Found {len(interesting)} interesting strings")
                        for s in interesting[:5]:
                            print(f"        {s.strip()}")

        elif ct == ChallengeType.FORENSICS:
            if os.path.isfile(filepath):
                print("  [*] Running forensics analysis...")
                result = self.executor.forensics.full_analysis(filepath)
                print(f"      {result.output[:500]}")
                self.memory.update_info("analysis", result.output[:1000])

        elif ct == ChallengeType.STEGO:
            if os.path.isfile(filepath):
                print("  [*] Running stego analysis...")
                result = self.executor.stego.full_analysis(filepath)
                print(f"      {result.output[:500]}")
                self.memory.update_info("analysis", result.output[:1000])

        elif ct == ChallengeType.CRYPTO:
            content = self._read_as_text(filepath)
            if content:
                print("  [*] Analyzing crypto...")
                result = self.executor.crypto.analyze_text(content[:2000])
                print(f"      {result.output[:500]}")
                self.memory.update_info("analysis", result.output[:1000])

        elif ct == ChallengeType.NETWORK:
            if os.path.isfile(filepath):
                print("  [*] Analyzing pcap...")
                result = self.executor.forensics.analyze_pcap(filepath)
                print(f"      {result.output[:500]}")
                self.memory.update_info("analysis", result.output[:1000])

        elif ct in (ChallengeType.WEB, ChallengeType.MISC):
            print("  [*] Probing target...")
            if self._is_url_or_ip(self.target):
                result = self.executor.web.probe(self.target)
                print(f"      {result.output[:500]}")
                self.memory.update_info("analysis", result.output[:1000])

        self._check_for_flags("initial_recon")
        print()

    def _step(self, step_num: int) -> bool:
        elapsed = time.time() - self.start_time
        print(f"\n{'='*65}")
        print(f"  STEP {step_num}/{self.max_steps}  [{elapsed:.0f}s]")
        print(f"{'='*65}")

        context = self.memory.get_context(last_n=10)
        challenge_summary = self._challenge_summary()

        print("[*] Planning...")
        plan = self.planner.plan(
            context, challenge_summary, step_num,
            self.challenge_info.challenge_type.value
        )

        print(f"    Strategy:   {plan['reasoning'][:160]}")
        print(f"    Action:     [{plan['action_type']}] {plan['action_detail'][:120]}")
        print(f"    Category:   {plan.get('category', '?')}")
        print(f"    Confidence: {plan.get('confidence', '?')}")

        print("[*] Executing...")
        result = self.executor.execute(plan["action_type"], plan["action_detail"])

        output = result.summary()
        print(f"    Result ({len(output)} chars):")
        for line in output.split("\n")[:15]:
            print(f"      {line[:130]}")
        if output.count("\n") > 15:
            print(f"      ... ({output.count(chr(10)) - 15} more lines)")

        step_obj = Step(
            step_number=step_num,
            action_type=plan["action_type"],
            command=plan["action_detail"],
            output=output[:2000],
            reasoning=plan["reasoning"],
            category=plan.get("category", ""),
            success=result.success,
            confidence=plan.get("confidence", ""),
        )
        self.memory.add_step(step_obj)

        if plan.get("lesson"):
            self.memory.add_lesson(plan["lesson"])
            self.memory.update_info("tools_used", [plan["action_type"]])

        if self._check_for_flags(f"step_{step_num}"):
            return False

        if step_num >= self.max_steps:
            print(f"\n[!] Max steps ({self.max_steps}) reached.")
            return False

        return True

    def _check_for_flags(self, source: str) -> bool:
        last_outputs = []
        if self.memory.steps:
            last_step = self.memory.steps[-1]
            last_outputs.append(last_step.output)

        combined = "\n".join(last_outputs)
        found = self.flags.extract(combined)

        if found:
            for flag in found:
                cleaned = self.flags.clean(flag.value)
                print(f"\n  *** FLAG: {cleaned} ***")
                self.memory.add_flag(Flag(
                    value=cleaned,
                    source=source,
                    step_number=self.step_count,
                ))
            return True
        return False

    def _challenge_summary(self) -> str:
        info = self.challenge_info
        parts = [
            f"Target: {self.target}",
            f"Challenge type: {info.challenge_type.value}",
            f"File type: {info.file_type}",
        ]
        for k, v in info.details.items():
            parts.append(f"  {k}: {v}")
        return "\n".join(parts)

    def _read_as_text(self, filepath: str) -> str:
        if not os.path.isfile(filepath):
            return ""
        try:
            with open(filepath, "r", errors="replace") as f:
                return f.read(5000)
        except Exception:
            return ""

    def _is_url_or_ip(self, s: str) -> bool:
        import re
        return bool(re.match(r"https?://|^\d+\.\d+\.\d+\.\d+", s))

    def _finish(self):
        elapsed = time.time() - self.start_time
        print(f"\n{'#'*65}")
        print(f"  ENGAGEMENT COMPLETE")
        print(f"  Target: {self.target}")
        print(f"  Steps:  {self.step_count}")
        print(f"  Time:   {elapsed:.1f}s")
        print(f"{'#'*65}")

        if self.memory.flags:
            print(f"\n  FLAGS ({len(self.memory.flags)}):")
            for f in self.memory.flags:
                print(f"    {f.value}")
                print(f"      Source: {f.source}")
        else:
            print("\n  No flags captured.")

        if self.memory.lessons:
            print(f"\n  LESSONS ({len(self.memory.lessons)}):")
            for l in self.memory.lessons:
                print(f"    - {l}")

        log_path = os.path.join(self.state_dir, "run.json")
        self.memory.save_to_file(log_path)
        print(f"\n  Log: {log_path}")


def main():
    parser = argparse.ArgumentParser(
        description="CTF Agent - Universal Autonomous Flag Capture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py ./challenge_binary
  python agent.py ./capture.pcap
  python agent.py ./encrypted.txt
  python agent.py ./mystery.png
  python agent.py 10.10.10.1
  python agent.py http://target.local
  python agent.py ./challenge_dir/
        """
    )
    parser.add_argument("target", help="File, directory, IP, or URL to attack")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="llama3.2")
    parser.add_argument("--max-steps", type=int, default=50)
    parser.add_argument("--step-timeout", type=int, default=60)
    parser.add_argument("--state-dir", default="./state")

    args = parser.parse_args()
    agent = Agent(args)

    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        agent._finish()
        sys.exit(1)


if __name__ == "__main__":
    main()
