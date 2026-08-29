"""Dev utility: re-render report.html from an existing report.json without
re-running the full analysis. Useful while iterating on reporter.py's
template. Run from the repo root with the package installed (`pip install -e .`)."""
import argparse
import json

from zairo.reporter import generate_reports


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", nargs="?", default="zairo_out", help="Directory containing report.json (and where report.html is (re)written)")
    args = parser.parse_args()

    with open(f"{args.output_dir}/report.json") as f:
        data = json.load(f)
    generate_reports(data, args.output_dir)


if __name__ == "__main__":
    main()
