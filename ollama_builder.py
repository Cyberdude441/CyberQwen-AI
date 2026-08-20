import ollama
import os


categories = [
    "crypto",
    "forensics",
    "steganography",
    "osint",
    "web_exploitation",
    "reverse_engineering",
    "pwn",
    "malware_analysis",
    "linux_security"
]


output_dir = "dataset/generated"

os.makedirs(
    output_dir,
    exist_ok=True
)


for category in categories:

    print(f"[+] Generating {category} dataset...")

    prompt = f"""
You are CyberQwen dataset engineer.

Create a QLoRA fine-tuning dataset for a cybersecurity AI.

Category:
{category}

Generate 20 realistic cybersecurity training examples.

Use ONLY JSONL format.

Each line must be:

{{"instruction":"",
"input":"",
"output":""}}

Requirements:

- CTF style challenges
- Real security scenarios
- Explain methodology
- Include relevant tools
- Include Linux commands when useful
- Explain concepts clearly

Do not use markdown.
Do not add ```json.
Return only JSONL.
"""


    response = ollama.chat(
        model="qwen3:8b",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )


    data = response["message"]["content"]


    # remove markdown if model adds it
    data = data.replace("```json", "")
    data = data.replace("```", "")


    file_path = os.path.join(
        output_dir,
        f"{category}.jsonl"
    )


    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(data.strip())


    print(f"[+] Saved {file_path}")


print("\nDataset generation completed!")
