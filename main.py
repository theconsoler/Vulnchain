import argparse
import json
from pathlib import Path
from parsers.normalizer import detect_and_parse

def main():
    parser = argparse.ArgumentParser(description="VulnChain -- Scanner Ingestor")
    parser.add_argument("input", help="Path to scanner file (.nessus / .xml / .csv)")
    parser.add_argument("--output", default="output/normalized_vulns.json")
    args = parser.parse_args()

    print(f"[*] Parsing: {args.input}")
    vulns = detect_and_parse(args.input)
    print(f"[+] Parsed {len(vulns)} vulnerability records")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    with open(out, "w") as f:
        json.dump([v.model_dump() for v in vulns], f, indent=2, default=str)

    print(f"[+] Output written to: {out}")

if __name__ == "__main__":
    main()
