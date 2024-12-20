import argparse
from tqdm import tqdm
import csv
import constants as constval
import jsonlines
import masint
import os
import logging

logger = logging.getLogger(__name__)


def load_data(eval_file_path):
    with jsonlines.open(eval_file_path) as reader:
        data = list(reader)

    return data


def run_eval_pipeline(llm, data, model_hash):
    inputs = []
    for item in data:
        inputs.append(make_prompt(item))
    answers = [] #TODO: how to eval on model hash?
    answer_ops = llm.generate(prompts=inputs, model_name=model_hash)
    for answer_op in answer_ops:
        answers.append(answer_op)
    return answers


def make_prompt(data):
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
    prompt += "File: " + data["source_code_path"] + "\n"
    prompt += "Line: " + str(data["line_number"]) + "\n"
    prompt += get_source_code(data)
    prompt += "====================================\n"
    prompt += "Read the following bug report.\n"
    prompt += "============ Bug Report ============\n"
    prompt += data["bug_report_text"]
    prompt += "====================================\n"
    prompt += "Based on the source code and the bug report, write a diff that fixes the bug.\n"
    prompt += "Use github diff format.\n"
    prompt += "Don't explain your diff, answer directly with the diff.\n"
    prompt += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"

    return prompt


def get_source_code(data):
    # Before and after lines to show
    before_lines = constval.LINES_BEFORE  # 5
    after_lines = constval.LINES_AFTER  # 5

    source_code = data["code"]

    lines = source_code.split("\n")

    line_number = data["line_number"]

    assert line_number is not None, data

    start_line = max(0, line_number - before_lines)
    end_line = min(len(lines), line_number + after_lines)

    source_code_with_line_numbers = ""

    for i, line in enumerate(lines[start_line:end_line], start=start_line):
        source_code_with_line_numbers += f"{line}\n"

    return source_code_with_line_numbers


def save_results(results, results_path):
    jsonlines_path = results_path

    with jsonlines.open(jsonlines_path, "w") as writer:
        for result in results:
            writer.write(result.data)

    # Split the file path into directory, filename without extension, and current extension
    base = os.path.splitext(jsonlines_path)[0]

    # Add the new extension to the base filename
    # Also save the results as csv
    csv_path = f"{base}" + ".csv"

    # Select the following column names to be saved in the CSV file
    columns = [
        "bug_report_path",
        "bug_report_text",
        "given_prompt",
        "diff_text",
        "generated_diff",
    ]

    with open(csv_path, "w") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=columns)
        writer.writeheader()

        for result in results:
            writer.writerow({k: result.data[k] for k in columns})


def main():
    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description="Build an evaluation pipeline for a coverity repair LLM."
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
        help="Path to the input dataset file to evaluate on",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="/app/duckpilot-coverity/dataset/tuning/results/gold-test-results.jsonlines",
        help="Name of the file to write eval results to",
    )
    parser.add_argument(
        "-m",
        "--model",
        default="meta-llama/Meta-Llama-3.1-8B-Instruct",
        help="Model hash that eval should use",
    )
    args = parser.parse_args()

    # Set up logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
    logger.info(f"\nLoading data from {args.input}\n")
    logger.info(f"\nWriting eval results to {args.output}\n")

    data = load_data(eval_file_path=args.input)
    
    llm = masint.SupermassiveIntelligence()

    results = run_eval_pipeline(llm, data, args.model)

    save_results(results, args.output)


# Entry point of the script
if __name__ == "__main__":
    main()
