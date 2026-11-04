"""Fixture-only command backend. Never invokes DKMS, rm, depmod, or id."""

import json
import os
from pathlib import Path
import sys


def main():
    allowed = (Path(__file__).resolve().parents[2] / ".workbench/tmp").resolve()
    root = Path(os.environ["HAILO_DKMS_FIXTURE"]).resolve()
    if not root.is_relative_to(allowed) or root == allowed:
        raise ValueError("fixture must be a private directory below .workbench/tmp")
    state_path = root / "state.json"
    state = json.loads(state_path.read_text())
    tool, *arguments = sys.argv[1:]
    state["calls"].append([tool, *arguments])
    state_path.write_text(json.dumps(state))

    def save(code=0):
        state_path.write_text(json.dumps(state))
        return code

    def confined(name):
        path = Path(name)
        if not path.resolve().is_relative_to(root):
            raise ValueError("refusing non-fixture path: " + name)
        return path

    action = "dkms-" + arguments[0] if tool == "dkms" else tool
    failure = state["failures"].get(action, 0)
    if failure and not (action == "dkms-remove" and state["partial"]):
        return save(failure)
    if tool == "id":
        assert arguments == ["-u"]
        print(state.get("uid", "0"))  # Prerequisite only; the real process stays non-root.
    elif tool == "dkms":
        assert arguments[0] in ("status", "remove") and arguments[1:3] == ["-m", "hailo_pci"]
        kernel = arguments[arguments.index("-k") + 1] if "-k" in arguments else None
        if arguments[0] == "status":
            assert kernel is not None
            for version, kernels in state["versions"].items():
                if kernel in kernels:
                    print(f"hailo_pci/{version}, {kernel}, x86_64: {kernels[kernel]}")
        else:
            version = arguments[arguments.index("-v") + 1]
            kernels = state["versions"].get(version, {})
            selected = [kernel] if kernel is not None else list(kernels)
            if not selected or any(k not in kernels for k in selected):
                return save(3)
            for selected_kernel in selected:
                key = version + "/" + selected_kernel
                installed = state["installed"].pop(key, None)
                if installed:
                    confined(installed).unlink()
                original = state["restore"].pop(key, None)
                if original:
                    source, target = map(confined, original)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source.rename(target)
                del kernels[selected_kernel]
                if failure:
                    return save(failure)
    else:
        raise ValueError("unexpected command (no standalone mutation is authorized): " + tool)
    return save()


if __name__ == "__main__":
    sys.exit(main())
