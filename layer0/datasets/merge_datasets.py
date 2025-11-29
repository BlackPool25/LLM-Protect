"""
Dataset Merger and Processor for Layer0

Merges multiple attack datasets into a unified JSONL format for testing.
"""

import csv
import json
import hashlib
from pathlib import Path
from typing import Optional

# Input files
REDTEAM_FILE = Path(r"c:\Users\mayur\Downloads\RedTeam_2K.csv")
JAILBREAK_FILE = Path(r"c:\Users\mayur\Downloads\JailBreakV_28K.csv")
MINI_JAILBREAK_FILE = Path(r"c:\Users\mayur\Downloads\mini_JailBreakV_28K.csv")

# Output
OUTPUT_DIR = Path(__file__).parent
UNIFIED_FILE = OUTPUT_DIR / "unified_attacks.jsonl"
STATS_FILE = OUTPUT_DIR / "dataset_stats.json"


def hash_text(text: str) -> str:
    """Create a short hash for deduplication."""
    return hashlib.md5(text.lower().strip().encode()).hexdigest()[:12]


def normalize_policy(policy: str) -> str:
    """Normalize policy/category names."""
    mapping = {
        "animal abuse": "animal_abuse",
        "violence": "violence",
        "fraud": "fraud",
        "economic harm": "economic_harm",
        "malware": "malware",
        "illegal activity": "illegal_activity",
        "bias": "bias",
        "hate speech": "hate_speech",
        "physical harm": "physical_harm",
        "government decision": "government_decision",
        "unethical behavior": "unethical_behavior",
        "political sensitivity": "political_sensitivity",
    }
    return mapping.get(policy.lower().strip(), policy.lower().replace(" ", "_"))


def process_redteam(seen_hashes: set) -> list[dict]:
    """Process RedTeam_2K.csv"""
    records = []
    
    if not REDTEAM_FILE.exists():
        print(f"⚠️  File not found: {REDTEAM_FILE}")
        return records
    
    with open(REDTEAM_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get("question", "").strip()
            if not text:
                continue
            
            h = hash_text(text)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            
            records.append({
                "id": f"redteam_{row.get('id', len(records))}",
                "text": text,
                "category": normalize_policy(row.get("policy", "unknown")),
                "source": row.get("from", "RedTeam"),
                "type": "direct",  # Direct harmful prompt
                "is_jailbreak": False,
                "original_query": None,
            })
    
    return records


def process_jailbreak(filepath: Path, prefix: str, seen_hashes: set) -> list[dict]:
    """Process JailBreakV CSV files."""
    records = []
    
    if not filepath.exists():
        print(f"⚠️  File not found: {filepath}")
        return records
    
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            jailbreak_query = row.get("jailbreak_query", "").strip()
            redteam_query = row.get("redteam_query", "").strip()
            
            if not jailbreak_query:
                continue
            
            # Add the jailbreak version
            h = hash_text(jailbreak_query)
            if h not in seen_hashes:
                seen_hashes.add(h)
                records.append({
                    "id": f"{prefix}_{row.get('id', len(records))}",
                    "text": jailbreak_query,
                    "category": normalize_policy(row.get("policy", "unknown")),
                    "source": row.get("from", "JailBreakV"),
                    "type": row.get("format", "Template").lower(),
                    "is_jailbreak": True,
                    "original_query": redteam_query if redteam_query != jailbreak_query else None,
                })
            
            # Also add the clean redteam query if different
            if redteam_query and redteam_query != jailbreak_query:
                h2 = hash_text(redteam_query)
                if h2 not in seen_hashes:
                    seen_hashes.add(h2)
                    records.append({
                        "id": f"{prefix}_clean_{row.get('id', len(records))}",
                        "text": redteam_query,
                        "category": normalize_policy(row.get("policy", "unknown")),
                        "source": row.get("from", "JailBreakV"),
                        "type": "direct",
                        "is_jailbreak": False,
                        "original_query": None,
                    })
    
    return records


def main():
    print("="*60)
    print("🔄 Dataset Merger for Layer0")
    print("="*60)
    
    seen_hashes: set = set()
    all_records: list[dict] = []
    
    # Process each dataset
    print("\n📂 Processing RedTeam_2K.csv...")
    redteam_records = process_redteam(seen_hashes)
    all_records.extend(redteam_records)
    print(f"   Added: {len(redteam_records)} records")
    
    print("\n📂 Processing JailBreakV_28K.csv...")
    jailbreak_records = process_jailbreak(JAILBREAK_FILE, "jailbreak", seen_hashes)
    all_records.extend(jailbreak_records)
    print(f"   Added: {len(jailbreak_records)} records")
    
    print("\n📂 Processing mini_JailBreakV_28K.csv...")
    mini_records = process_jailbreak(MINI_JAILBREAK_FILE, "mini", seen_hashes)
    all_records.extend(mini_records)
    print(f"   Added: {len(mini_records)} records")
    
    # Calculate stats
    stats = {
        "total_records": len(all_records),
        "unique_hashes": len(seen_hashes),
        "by_category": {},
        "by_type": {},
        "by_source": {},
        "jailbreak_count": sum(1 for r in all_records if r["is_jailbreak"]),
        "direct_count": sum(1 for r in all_records if not r["is_jailbreak"]),
    }
    
    for record in all_records:
        cat = record["category"]
        typ = record["type"]
        src = record["source"]
        
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        stats["by_type"][typ] = stats["by_type"].get(typ, 0) + 1
        stats["by_source"][src] = stats["by_source"].get(src, 0) + 1
    
    # Write unified JSONL
    print(f"\n💾 Writing unified dataset to {UNIFIED_FILE}...")
    with open(UNIFIED_FILE, "w", encoding="utf-8") as f:
        for record in all_records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    
    # Write stats
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    
    # Print summary
    print(f"\n{'='*60}")
    print("📊 SUMMARY")
    print(f"{'='*60}")
    print(f"   Total Records:     {stats['total_records']}")
    print(f"   Jailbreak Prompts: {stats['jailbreak_count']}")
    print(f"   Direct Prompts:    {stats['direct_count']}")
    print(f"\n   By Category:")
    for cat, count in sorted(stats["by_category"].items(), key=lambda x: -x[1]):
        print(f"      {cat}: {count}")
    
    print(f"\n✅ Unified dataset saved to: {UNIFIED_FILE}")
    print(f"✅ Stats saved to: {STATS_FILE}")


if __name__ == "__main__":
    main()
