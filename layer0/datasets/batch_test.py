"""
Batch Test Layer0 with Attack Dataset

Tests the Layer0 server against the unified attack dataset and reports detection rates.
"""

import json
import time
import httpx
from pathlib import Path
from collections import defaultdict

# Configuration
LAYER0_URL = "http://localhost:3001/layer0"
DATASET_FILE = Path(__file__).parent / "unified_attacks.jsonl"
RESULTS_FILE = Path(__file__).parent / "test_results.json"


def load_dataset() -> list[dict]:
    """Load the unified attack dataset."""
    records = []
    with open(DATASET_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def test_single(client: httpx.Client, text: str) -> dict:
    """Send a single test to Layer0."""
    payload = {
        "prepared_input": {
            "text_embed_stub": {
                "normalized_user": text,
                "normalized_external": []
            }
        }
    }
    
    try:
        response = client.post(LAYER0_URL, json=payload, timeout=10.0)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def main():
    print("="*60)
    print("🧪 Layer0 Batch Testing")
    print("="*60)
    
    # Load dataset
    print(f"\n📂 Loading dataset from {DATASET_FILE}...")
    try:
        records = load_dataset()
    except FileNotFoundError:
        print("❌ Dataset not found. Run merge_datasets.py first!")
        return
    
    print(f"   Loaded {len(records)} attack prompts")
    
    # Initialize counters
    results = {
        "total": len(records),
        "blocked": 0,
        "flagged": 0,
        "passed": 0,
        "errors": 0,
        "by_category": defaultdict(lambda: {"blocked": 0, "flagged": 0, "passed": 0}),
        "by_type": defaultdict(lambda: {"blocked": 0, "flagged": 0, "passed": 0}),
        "detection_rate": 0.0,
        "samples": {"blocked": [], "flagged": [], "passed": []},
    }
    
    # Test each record
    print("\n🔄 Testing against Layer0...")
    start_time = time.time()
    
    with httpx.Client() as client:
        for i, record in enumerate(records):
            if (i + 1) % 100 == 0:
                print(f"   Progress: {i+1}/{len(records)}")
            
            text = record["text"]
            category = record["category"]
            rec_type = record["type"]
            
            response = test_single(client, text)
            
            if "error" in response:
                results["errors"] += 1
                continue
            
            verdict = response.get("layer0_verdict", "").lower()
            
            if verdict == "block":
                results["blocked"] += 1
                results["by_category"][category]["blocked"] += 1
                results["by_type"][rec_type]["blocked"] += 1
                if len(results["samples"]["blocked"]) < 5:
                    results["samples"]["blocked"].append({
                        "text": text[:200],
                        "category": category,
                        "signatures": response.get("signatures", [])
                    })
            elif verdict == "flag":
                results["flagged"] += 1
                results["by_category"][category]["flagged"] += 1
                results["by_type"][rec_type]["flagged"] += 1
                if len(results["samples"]["flagged"]) < 5:
                    results["samples"]["flagged"].append({
                        "text": text[:200],
                        "category": category,
                        "signatures": response.get("signatures", [])
                    })
            else:
                results["passed"] += 1
                results["by_category"][category]["passed"] += 1
                results["by_type"][rec_type]["passed"] += 1
                if len(results["samples"]["passed"]) < 10:
                    results["samples"]["passed"].append({
                        "text": text[:200],
                        "category": category,
                    })
    
    elapsed = time.time() - start_time
    
    # Calculate detection rate
    detected = results["blocked"] + results["flagged"]
    tested = results["total"] - results["errors"]
    results["detection_rate"] = (detected / tested * 100) if tested > 0 else 0
    results["elapsed_seconds"] = round(elapsed, 2)
    
    # Convert defaultdicts to regular dicts for JSON
    results["by_category"] = dict(results["by_category"])
    results["by_type"] = dict(results["by_type"])
    
    # Save results
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print(f"\n{'='*60}")
    print("📊 RESULTS")
    print(f"{'='*60}")
    print(f"   Total Tested:    {tested}")
    print(f"   Blocked:         {results['blocked']} ({results['blocked']/tested*100:.1f}%)")
    print(f"   Flagged:         {results['flagged']} ({results['flagged']/tested*100:.1f}%)")
    print(f"   Passed:          {results['passed']} ({results['passed']/tested*100:.1f}%)")
    print(f"   Errors:          {results['errors']}")
    print(f"   Detection Rate:  {results['detection_rate']:.1f}%")
    print(f"   Time:            {elapsed:.1f}s ({tested/elapsed:.1f} req/s)")
    
    print(f"\n   By Category:")
    for cat, counts in sorted(results["by_category"].items()):
        total = counts["blocked"] + counts["flagged"] + counts["passed"]
        det = counts["blocked"] + counts["flagged"]
        rate = det / total * 100 if total > 0 else 0
        print(f"      {cat}: {det}/{total} detected ({rate:.0f}%)")
    
    if results["samples"]["passed"]:
        print(f"\n⚠️  Sample PASSED attacks (need rules):")
        for sample in results["samples"]["passed"][:5]:
            print(f"      [{sample['category']}] {sample['text'][:80]}...")
    
    print(f"\n✅ Full results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
