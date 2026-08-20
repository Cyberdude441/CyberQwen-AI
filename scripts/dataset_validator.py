import json
import os

DATASET_PATH = "../dataset"

required_fields = [
    "instruction",
    "input",
    "output"
]


def validate_file(file_path):
    print(f"\nChecking: {file_path}")

    errors = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):

            try:
                data = json.loads(line)

                for field in required_fields:
                    if field not in data:
                        print(
                            f"Missing {field} at line {line_number}"
                        )
                        errors += 1

            except Exception as e:
                print(
                    f"Invalid JSON at line {line_number}: {e}"
                )
                errors += 1

    if errors == 0:
        print("✅ Dataset OK")
    else:
        print(f"❌ Found {errors} problems")


for root, dirs, files in os.walk(DATASET_PATH):
    for file in files:
        if file.endswith(".jsonl"):
            validate_file(
                os.path.join(root, file)
            )