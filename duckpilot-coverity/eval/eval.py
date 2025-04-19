import masint
import argparse
import csv
import constants as constval
import jsonlines
import os
import logging
from prompt import prompt_template

masint.api_url = "https://llama8btensorwave.cray-lm.com/"
# masint.api_url = "http://localhost:8000"

logger = logging.getLogger(__name__)

import re


def format_diff(raw_diff):
    # Extract the diff content
    diff_match = re.search(r"```diff\n(.*?)\n```", raw_diff, re.DOTALL)
    if not diff_match:
        return "Invalid diff format"

    diff_content = diff_match.group(1)

    # Extract file name
    file_match = re.search(r"diff --git a/(.*?) b/.*", diff_content)
    file_name = file_match.group(1) if file_match else "Unknown file"

    # Extract note
    note_match = re.search(r"```={36}\n(.*)", raw_diff, re.DOTALL)
    note = note_match.group(1).strip() if note_match else ""

    # Format the readable output
    formatted_output = f"""
        File: {file_name}
        ```diff
        {diff_content}
        ```

        Note:
        {note if note else 'No additional notes.'}
        """.strip()

    return formatted_output


def load_data(eval_file_path):
    with jsonlines.open(eval_file_path) as reader:
        data = list(reader)

    return data


def get_dataset(data):
    dataset = []
    for i in range(len(data)):
        print(f"data[{i}] contains {data[i].keys()}")
        entry = prompt_template.format(
            source_code_path=data[i]["source_code_path"],
            line_number=data[i]["line_number"],
            code=get_source_code(data[i]),
            bug_report_text=data[i]["bug_report_text"],
        )
        dataset.append(entry)

    logger.info(f"\nGenerated {len(dataset)} prompts")
    return dataset


def get_source_code(data):
    # Before and after lines to show
    before_lines = constval.LINES_BEFORE
    after_lines = constval.LINES_AFTER

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

    logger.info(f"Writing to file {jsonlines_path}")
    with jsonlines.open(jsonlines_path, "w") as writer:
        for result in results:
            writer.write(result)

    # Split the file path into directory, filename without extension, and current extension
    base = os.path.splitext(jsonlines_path)[0]

    # Add the new extension to the base filename
    # Also save the results as csv
    """csv_path = f"{base}" + ".csv"

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
            writer.writerow({k: result[k] for k in columns})"""


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
        default=None,
        help="Model hash that eval should use",
    )
    args = parser.parse_args()

    # Set up logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    logger.info(f"\nLoading data from {args.input}\n")

    logger.info(f"\nWriting eval results to {args.output}\n")

    data = load_data(eval_file_path=args.input)
    dataset = get_dataset(data)

    llm = masint.SupermassiveIntelligence()

    import time

    # Capture start time
    start_time = time.time()
    results = []
    i = 0

    iter_start_time = time.time()
    print(f"\n\n{dataset[0]}\n\n")
    generated_diffs = llm.generate(
        prompts=dataset, max_tokens=256, model_name=args.model
    )
    iter_end_time = time.time()

    iteration_latency = iter_end_time - iter_start_time
    print(f"Generated Result {i} - Iteration Time: {iteration_latency:.4f} seconds")

    for i in range(0, len(generated_diffs)):
        this_result = {}
        this_result["bug_report_path"] = data[i]["source_code_path"]
        this_result["bug_report_text"] = data[i]["bug_report_text"]
        this_result["given_prompt"] = dataset[i]
        this_result["diff_text"] = data[i]["diff_text"]
        this_result["generated_diff"] = generated_diffs[
            i
        ]  # format_diff(generated_diff[0])
        results.append(this_result)
        # print(f"generated diff \n{generated_diffs[i]}\n")
        # print(f"formatted diff\n\n{format_diff(generated_diffs[i])}\n")
        i += 1
        print(f"\n Prompt contains \n {this_result['given_prompt']}")

    end_time = time.time()
    total_latency = end_time - start_time

    print(f"Total loop execution time: {total_latency:.4f} seconds")
    print(results)
    save_results(results, args.output)


# Entry point of the script
if __name__ == "__main__":
    main()
