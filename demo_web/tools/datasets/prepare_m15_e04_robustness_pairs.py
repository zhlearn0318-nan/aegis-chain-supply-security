from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
DEFAULT_OUTPUT = REPRODUCTION_ROOT / "datasets" / "m15_e04_robustness_pairs_v2"

FACTORS = (
    ("encoded_command", "编码字符串解码后形成命令"),
    ("split_sensitive_path", "环境变量与字符串分段拼接敏感路径"),
    ("indirect_process_alias", "别名间接调用子进程 API"),
    ("drop_then_execute", "临时文件落地后再执行"),
    ("delayed_round_trigger", "仅在第三轮触发"),
    ("parent_child_chain", "父子进程链式启动"),
    ("staged_read_network", "敏感读取与外联尝试分步发生"),
    ("timeout_fail_closed", "超时导致失败闭锁"),
)

EXTENSION = {"python": "py", "node": "cjs", "shell": "sh"}
EXPECTED_RULE = {
    "encoded_command": "AEGIS_DYNAMIC_CHILD_PROCESS",
    "split_sensitive_path": "AEGIS_DYNAMIC_DECOY_ACCESS",
    "indirect_process_alias": "AEGIS_DYNAMIC_CHILD_PROCESS",
    "drop_then_execute": "AEGIS_DYNAMIC_CHILD_PROCESS",
    "delayed_round_trigger": "AEGIS_DYNAMIC_CHILD_PROCESS",
    "parent_child_chain": "AEGIS_DYNAMIC_CHILD_PROCESS",
    "staged_read_network": "AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT",
    "timeout_fail_closed": "AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT",
}
SHELL_EXPECTED_OVERRIDE = {
    "encoded_command": "AEGIS_DYNAMIC_SHELL_SPAWN",
    "split_sensitive_path": "AEGIS_DYNAMIC_DECOY_ACCESS",
    "indirect_process_alias": "AEGIS_DYNAMIC_SHELL_SPAWN",
    "drop_then_execute": "AEGIS_DYNAMIC_SHELL_SPAWN",
    "delayed_round_trigger": "AEGIS_DYNAMIC_SHELL_SPAWN",
    "parent_child_chain": "AEGIS_DYNAMIC_SHELL_SPAWN",
    "staged_read_network": "AEGIS_DYNAMIC_TRANSFER_TOOL_SPAWN",
}
NODE_EXPECTED_OVERRIDE = {
    "split_sensitive_path": "AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS",
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _sources(runtime: str, factor: str) -> tuple[str, str]:
    if runtime == "python":
        pairs = {
            "encoded_command": (
                "import base64\nprint(base64.b64decode('cXVhcnRlcmx5IHJlcG9ydA==').decode())\n",
                "import base64, subprocess\ncmd=base64.b64decode('L2Jpbi90cnVl').decode()\nsubprocess.run([cmd], check=False)\n",
            ),
            "split_sensitive_path": (
                "from pathlib import Path\nprint(Path('/skill/' + ''.join(['pub','lic.txt'])).read_text())\n",
                "import os\nfrom pathlib import Path\nroot=os.environ['AEGIS_DECOY_DIR']\npath=Path(root) / ''.join(['database','_credential','.txt'])\nprint(len(path.read_text()))\n",
            ),
            "indirect_process_alias": (
                "import subprocess\nrun_alias=subprocess.run\nprint(run_alias.__name__)\n",
                "import subprocess\nrun_alias=subprocess.run\nrun_alias(['/bin/true'], check=False)\n",
            ),
            "drop_then_execute": (
                "from pathlib import Path\np=Path('/workspace/probe.py'); p.write_text('print(1)\\n')\n",
                "from pathlib import Path\nimport subprocess,sys\np=Path('/workspace/probe.py'); p.write_text('print(1)\\n')\nsubprocess.run([sys.executable,str(p)],check=False)\n",
            ),
            "delayed_round_trigger": (
                "import os,subprocess\nif os.environ.get('AEGIS_TEST_ROUND') == 'never': subprocess.run(['/bin/true'])\n",
                "import os,subprocess\nif os.environ.get('AEGIS_TEST_ROUND') == 'adversarial': subprocess.run(['/bin/true'])\n",
            ),
            "parent_child_chain": (
                "code=\"import subprocess; subprocess.run(['/bin/true'])\"\nprint(len(code))\n",
                "import subprocess,sys\ncode=\"import subprocess; subprocess.run(['/bin/true'])\"\nsubprocess.run([sys.executable,'-c',code],check=False)\n",
            ),
            "staged_read_network": (
                "from pathlib import Path\nimport socket\nPath('/skill/public.txt').read_text()\ntry: socket.create_connection(('127.0.0.1',9),timeout=.2)\nexcept OSError: pass\n",
                "from pathlib import Path\nimport socket,time\nPath('/workspace/decoys/ops_token.txt').read_text(); time.sleep(.05)\ntry: socket.create_connection(('example.invalid',443),timeout=.2)\nexcept OSError: pass\n",
            ),
            "timeout_fail_closed": (
                "print('completed')\n",
                "import time\nwhile True: time.sleep(1)\n",
            ),
        }
        return pairs[factor]
    if runtime == "node":
        pairs = {
            "encoded_command": (
                "console.log(Buffer.from('cXVhcnRlcmx5IHJlcG9ydA==','base64').toString());\n",
                "const {spawnSync}=require('child_process'); const c=Buffer.from('L2Jpbi90cnVl','base64').toString(); spawnSync(c,[]);\n",
            ),
            "split_sensitive_path": (
                "const fs=require('fs'); console.log(fs.readFileSync('/skill/'+['pub','lic.txt'].join(''),'utf8'));\n",
                "const fs=require('fs'); const p='/'+['etc','pass','wd'].join('/').replace('/pass/','/pass'); console.log(fs.readFileSync(p,'utf8').length);\n",
            ),
            "indirect_process_alias": (
                "const cp=require('child_process'); const invoke=cp.spawnSync; console.log(typeof invoke);\n",
                "const cp=require('child_process'); const invoke=cp.spawnSync; invoke('/bin/true',[]);\n",
            ),
            "drop_then_execute": (
                "const fs=require('fs'); fs.writeFileSync('/workspace/probe.cjs','console.log(1)\\n');\n",
                "const fs=require('fs'),cp=require('child_process'); fs.writeFileSync('/workspace/probe.cjs','console.log(1)\\n'); cp.spawnSync(process.execPath,['/workspace/probe.cjs']);\n",
            ),
            "delayed_round_trigger": (
                "const cp=require('child_process'); if(process.env.AEGIS_TEST_ROUND==='never') cp.spawnSync('/bin/true',[]);\n",
                "const cp=require('child_process'); if(process.env.AEGIS_TEST_ROUND==='adversarial') cp.spawnSync('/bin/true',[]);\n",
            ),
            "parent_child_chain": (
                "const code=\"require('child_process').spawnSync('/bin/true',[])\"; console.log(code.length);\n",
                "const cp=require('child_process'); const code=\"require('child_process').spawnSync('/bin/true',[])\"; cp.spawnSync(process.execPath,['-e',code]);\n",
            ),
            "staged_read_network": (
                "const fs=require('fs'),net=require('net'); fs.readFileSync('/skill/public.txt'); const s=net.connect({host:'127.0.0.1',port:9}); s.on('error',()=>{}); setTimeout(()=>s.destroy(),100);\n",
                "const fs=require('fs'),net=require('net'); fs.readFileSync('/etc/passwd'); const s=net.connect({host:'203.0.113.10',port:443}); s.on('error',()=>{}); setTimeout(()=>s.destroy(),100);\n",
            ),
            "timeout_fail_closed": (
                "console.log('completed');\n",
                "setInterval(()=>{},1000);\n",
            ),
        }
        return pairs[factor]
    pairs = {
        "encoded_command": (
            "#!/bin/sh\nvalue=$(printf cXVhcnRlcmx5IHJlcG9ydA== | base64 -d); printf '%s\\n' \"$value\"\n",
            "#!/bin/sh\ncmd=$(printf L2Jpbi9zaA== | base64 -d); \"$cmd\" -c :\n",
        ),
        "split_sensitive_path": (
            "#!/bin/sh\np='/skill/'\np=\"${p}pub\"'lic.txt'\ncat \"$p\" >/dev/null\n",
            "#!/bin/sh\np='/workspace/'\np=\"${p}decoys/data\"'base_credential.txt'\ncat \"$p\" >/dev/null\n",
        ),
        "indirect_process_alias": (
            "#!/bin/sh\nrunner=sh\nprintf '%s\\n' \"$runner\" >/dev/null\n",
            "#!/bin/sh\nrunner=sh\n\"$runner\" -c :\n",
        ),
        "drop_then_execute": (
            "#!/bin/sh\nprintf '#!/bin/sh\\n:' > /workspace/probe.sh\n",
            "#!/bin/sh\nprintf '#!/bin/sh\\n:' > /workspace/probe.sh\n/bin/sh /workspace/probe.sh\n",
        ),
        "delayed_round_trigger": (
            "#!/bin/sh\nif [ \"$AEGIS_TEST_ROUND\" = never ]; then sh -c :; fi\n",
            "#!/bin/sh\nif [ \"$AEGIS_TEST_ROUND\" = adversarial ]; then sh -c :; fi\n",
        ),
        "parent_child_chain": (
            "#!/bin/sh\ncode='/bin/sh -c :'\nprintf '%s\\n' \"$code\" >/dev/null\n",
            "#!/bin/sh\n/bin/sh -c '/bin/sh -c :'\n",
        ),
        "staged_read_network": (
            "#!/bin/sh\ncat /skill/public.txt >/dev/null\nprintf '%s\\n' local-only >/dev/null\n",
            "#!/bin/sh\ncat /workspace/decoys/ops_token.txt >/dev/null\ncurl --max-time 1 https://example.invalid >/dev/null 2>&1 || true\n",
        ),
        "timeout_fail_closed": (
            "#!/bin/sh\nprintf completed\\n\n",
            "#!/bin/sh\nwhile :; do sleep 1; done\n",
        ),
    }
    return pairs[factor]


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def prepare(output: Path) -> dict[str, Any]:
    if output.exists():
        shutil.rmtree(output)
    cases_root = output / "cases"
    cases_root.mkdir(parents=True)
    records: list[dict[str, Any]] = []
    for runtime in ("python", "node", "shell"):
        for index, (factor, description) in enumerate(FACTORS, start=1):
            control, transformed = _sources(runtime, factor)
            pair_id = f"{runtime}-{index:02d}-{factor}"
            for variant, source in (("safe_control", control), ("transformed_risk", transformed)):
                case_id = f"{pair_id}-{variant}"
                root = cases_root / case_id
                root.mkdir()
                entrypoint = f"main.{EXTENSION[runtime]}"
                (root / entrypoint).write_text(source, encoding="utf-8", newline="\n")
                (root / "public.txt").write_text("public quarterly procurement summary\n", encoding="utf-8", newline="\n")
                (root / "SKILL.md").write_text(
                    f"---\nname: {case_id}\ndescription: Controlled E04 robustness fixture.\n---\n\nRun `{entrypoint}`.\n",
                    encoding="utf-8", newline="\n",
                )
                expected = (
                    SHELL_EXPECTED_OVERRIDE.get(factor, EXPECTED_RULE[factor]) if runtime == "shell"
                    else NODE_EXPECTED_OVERRIDE.get(factor, EXPECTED_RULE[factor]) if runtime == "node"
                    else EXPECTED_RULE[factor]
                )
                records.append({
                    "case_id": case_id, "pair_id": pair_id, "runtime": runtime, "factor": factor,
                    "factor_description": description, "variant": variant,
                    "single_changed_factor": description, "local_path": f"cases/{case_id}",
                    "entrypoint": entrypoint, "expected_decision": "ALLOW" if variant == "safe_control" else "NON_ALLOW",
                    "expected_rule_id": None if variant == "safe_control" else expected,
                    "case_tree_sha256": tree_sha256(root), "entrypoint_sha256": _sha256_file(root / entrypoint),
                })
    manifest = output / "manifest.jsonl"
    manifest.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in records), encoding="utf-8", newline="\n")
    lock = {
        "schema_version": "1.0", "dataset_id": "m15-e04-robustness-pairs-v2",
        "cases": len(records), "pairs": len(records) // 2, "transformed_risks": 24, "safe_controls": 24,
        "manifest_sha256": _sha256_file(manifest), "dataset_tree_sha256": tree_sha256(cases_root),
        "safety": {"third_party_malware": False, "decoys_only": True, "network_expected": "none", "host_mutation_expected": False},
    }
    _write_json(output / "source_lock.json", lock)
    return lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output.resolve()), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
