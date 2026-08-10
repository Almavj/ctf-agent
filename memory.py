"""Memory module: tracks full engagement state."""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Step:
    step_number: int
    action_type: str
    command: str
    output: str
    reasoning: str
    category: str = ""
    success: Optional[bool] = None
    confidence: str = ""
    timestamp: float = field(default_factory=time.time)
    lesson: str = ""

    def to_dict(self):
        d = asdict(self)
        d["output"] = d["output"][:2000]
        return d


@dataclass
class Flag:
    value: str
    source: str
    step_number: int
    timestamp: float = field(default_factory=time.time)


class Memory:
    def __init__(self, state_dir: str = "./state"):
        self.state_dir = state_dir
        self.steps: list[Step] = []
        self.flags: list[Flag] = []
        self.lessons: list[str] = []
        self.challenge_info: dict = {
            "input": "",
            "challenge_type": "",
            "file_type": "",
            "files_found": [],
            "interesting_strings": [],
            "credentials": [],
            "vulnerabilities": [],
            "tools_used": [],
            "extracted_files": [],
        }
        os.makedirs(state_dir, exist_ok=True)
        self._load()

    def add_step(self, step: Step):
        self.steps.append(step)
        self._save()

    def add_flag(self, flag: Flag):
        self.flags.append(flag)
        self._save()

    def add_lesson(self, lesson: str):
        if lesson and lesson not in self.lessons:
            self.lessons.append(lesson)

    def update_info(self, key: str, value):
        if key in self.challenge_info:
            if isinstance(self.challenge_info[key], list):
                if isinstance(value, list):
                    for v in value:
                        if v not in self.challenge_info[key]:
                            self.challenge_info[key].append(v)
                else:
                    if value not in self.challenge_info[key]:
                        self.challenge_info[key].append(value)
            else:
                self.challenge_info[key] = value
        self._save()

    def get_context(self, last_n: int = 12) -> str:
        parts = []
        parts.append("=== ENGAGEMENT STATE ===")
        parts.append("")
        parts.append("DISCOVERED:")
        for key, val in self.challenge_info.items():
            if val:
                if isinstance(val, list):
                    if val:
                        parts.append(f"  {key}: {', '.join(str(v) for v in val[:15])}")
                else:
                    parts.append(f"  {key}: {val}")
        parts.append("")

        if self.flags:
            parts.append("FLAGS CAPTURED:")
            for f in self.flags:
                parts.append(f"  {f.value} (from {f.source})")
            parts.append("")

        if self.lessons:
            parts.append("LESSONS:")
            for lesson in self.lessons[-8:]:
                parts.append(f"  - {lesson}")
            parts.append("")

        recent = self.steps[-last_n:]
        parts.append(f"ACTIONS ({len(self.steps)} total):")
        for s in recent:
            status = "OK" if s.success else ("FAIL" if s.success is False else "?")
            parts.append(f"  [{s.step_number}] ({status}) [{s.category}] {s.command[:120]}")
            if s.output:
                preview = s.output[:250].replace("\n", " | ")
                parts.append(f"       -> {preview}")

        return "\n".join(parts)

    def save_to_file(self, filepath: str):
        data = {
            "steps": [s.to_dict() for s in self.steps],
            "flags": [asdict(f) for f in self.flags],
            "lessons": self.lessons,
            "challenge_info": self.challenge_info,
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def _save(self):
        self.save_to_file(os.path.join(self.state_dir, "memory.json"))

    def _load(self):
        path = os.path.join(self.state_dir, "memory.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                self.lessons = data.get("lessons", [])
                self.challenge_info.update(data.get("challenge_info", {}))
                self.steps = [Step(**s) for s in data.get("steps", [])]
                self.flags = [Flag(**f) for f in data.get("flags", [])]
            except Exception:
                pass
