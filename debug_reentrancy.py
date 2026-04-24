"""Quick diagnostic to see why real Hardhat reentrancy tests fail."""
import json, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from scanner import engine
from simulation.service import run_runtime_validation

source = open("samples/reentrancy.sol", "r", encoding="utf-8").read()
scan_result = engine.scan(source, "reentrancy.sol")

print("=" * 60)
print("REENTRANCY FINDINGS FROM STATIC SCAN:")
for f in scan_result["findings"]:
    if f["check"] == "reentrancy":
        print(f"  id={f['id']}")
        print(f"  function={f.get('function')}")
        print(f"  contract_name={f.get('contract_name')}")
        print()

print("=" * 60)
print("RUNNING RUNTIME VALIDATION...")
result = run_runtime_validation(source, scan_result["findings"])

print(f"\nOverall status: {result['status']}")
print(f"Overall summary: {result['summary']}")
print(f"Overall error: {result.get('error')}")
print(f"Validation count: {len(result.get('validations', []))}")

for i, v in enumerate(result.get("validations", [])):
    if v["check"] == "reentrancy":
        print(f"\n--- Reentrancy Validation #{i} ---")
        print(f"  status: {v['status']}")
        print(f"  error: {v.get('error')}")
        print(f"  scenario: {v.get('scenario')}")
        print(f"  contract_name: {v.get('contract_name')}")
        print(f"  function_name: {v.get('function_name')}")
        print(f"  evidence: {json.dumps(v.get('evidence', {}), indent=4)}")
        print(f"  limitations: {v.get('limitations')}")
        if v.get("actions"):
            for j, a in enumerate(v["actions"]):
                print(f"  action[{j}]: {a.get('action')} status={a.get('status')} reverted={a.get('reverted')} error={a.get('error')}")
