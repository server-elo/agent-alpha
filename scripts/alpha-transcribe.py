#!/usr/bin/env python3
"""Transcribe a Telegram voice note to text on stdout.

Local Whisper only -- no API key, no network. Prints nothing but the
transcript, so the caller can splice it straight into a chat turn.

Language is pinned rather than auto-detected: on short, noisy phone audio
auto-detect guessed Latvian and then Lithuanian for clearly English speech
and produced pure gibberish, while the same model with an explicit language
transcribed it correctly. ALPHA_VOICE_LANG overrides (e.g. "de").

An initial_prompt of project jargon is passed as well. Whisper conditions on
it as if it were preceding transcript, so words it would otherwise spell as
ordinary English come out right: "Goldcrit" -> "buildcrit", "fan out" ->
"fanout", "Cargo Clippy" -> "cargo clippy". It biases, it does not constrain,
so ordinary speech is unaffected. ALPHA_VOICE_PROMPT overrides.
"""
import os
import sys

MODEL = os.environ.get("ALPHA_VOICE_MODEL", "medium")
LANG = os.environ.get("ALPHA_VOICE_LANG", "en")
DEFAULT_PROMPT = (
    "Working on buildcrit, agent-alpha, ninja, bazel, cargo, JSON, DAG, "
    "fanout, makespan, critical path, CI, MSRV, clippy, rustfmt, GitHub, "
    "README, repo, commit, push, stdout, stderr, fd, setsid, whisper."
)
PROMPT = os.environ.get("ALPHA_VOICE_PROMPT", DEFAULT_PROMPT)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: alpha-transcribe.py <audio-file>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"no such file: {path}", file=sys.stderr)
        return 1

    try:
        import whisper
    except ImportError:
        print("whisper is not installed", file=sys.stderr)
        return 1

    try:
        model = whisper.load_model(MODEL)
        result = model.transcribe(
            path, language=LANG, fp16=False, initial_prompt=PROMPT or None
        )
    except Exception as exc:                     # noqa: BLE001 - report, do not crash the agent
        print(f"transcription failed: {exc}", file=sys.stderr)
        return 1

    text = (result.get("text") or "").strip()
    if not text:
        print("empty transcript", file=sys.stderr)
        return 1
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
