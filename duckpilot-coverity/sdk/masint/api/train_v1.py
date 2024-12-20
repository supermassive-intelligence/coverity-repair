import argparse
import constants as constval
import jsonlines
import logging
import masint

logger = logging.getLogger(__name__)


def print_data(data):
    for item in data:
        print(item["input"])
        print(item["output"])
        print()


def get_data(training_data_file):
    raw_data = get_raw_data(training_data_file)

    data = []

    for item in raw_data:
        prompt = make_prompt(item)
        data.append(
            {
                "input": prompt,
                "output": item["diff_text"] + "<|eot_id|>",
            }
        )
    # random.seed(42)
    # random.shuffle(data)

    return data


def get_raw_data(training_data_file):
    with jsonlines.open(training_data_file) as reader:
        data = list(reader)

    return data


def make_prompt(item):
    prompt = "<|start_header_id|>user<|end_header_id|>"
    prompt += "Consider the following github diff format.\n"
    prompt += "============ Diff format ============\n"
    prompt += "```diff\n"
    prompt += "diff --git a/file1 b/file2\n"
    prompt += "index 1234567..89abcdef 100644\n"
    prompt += "--- a/file1\n"
    prompt += "+++ b/file2\n"
    prompt += "@@ -1,3 +1,3 @@\n"
    prompt += "-old line\n"
    prompt += "+new line\n"
    prompt += "```"
    prompt += "====================================\n"
    prompt += "Read through the following source code carefully.\n"
    prompt += "============ Source Code ============\n"
    prompt += "File: " + item["source_code_path"] + "\n"
    prompt += "Line: " + str(item["line_number"]) + "\n"
    prompt += get_source_code(item)
    prompt += "====================================\n"
    prompt += "Read the following bug report.\n"
    prompt += "============ Bug Report ============\n"
    prompt += item["bug_report_text"]
    prompt += "====================================\n"
    prompt += "Based on the source code and the bug report, write a diff that fixes the bug.\n"
    prompt += "Use github diff format.\n"
    prompt += "Don't explain your diff, answer directly with the diff.\n"
    prompt += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"

    return prompt


def get_source_code(data):
    # Before and after lines to show
    before_lines = 5
    after_lines = 5

    source_code = data["code"]

    lines = source_code.split("\n")

    line_number = data["line_number"]

    start_line = max(0, line_number - before_lines)
    end_line = min(len(lines), line_number + after_lines)

    source_code_with_line_numbers = ""

    for i, line in enumerate(lines[start_line:end_line], start=start_line):
        source_code_with_line_numbers += f"{line}\n"

    return source_code_with_line_numbers


def main():
    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description="Build a tuning pipeline for a coverity repair LLM."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose mode (sets logging to DEBUG level)",
    )
    parser.add_argument(
        "-i",
        "--input",
        default="/app/duckpilot-coverity/dataset/tuning/inputs/gold-test-set.jsonlines",
        help="Path to the input dataset file to tune on",
    )
    args = parser.parse_args()

    # Set up logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    data = get_data(training_data_file=args.input)

    print_data(data)

    llm = masint.SupermassiveIntelligence()
    status = llm.train(data=data, train_args={"max_steps": 100,
            "learning_rate": 3.0e-4,
            "batch_size": 1,})
    print(f"Status of training job is: {status}")
    #TODO: poll to wait for specific status?


# Entry point of the script
if __name__ == "__main__":
    main()
