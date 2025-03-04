import jsonlines
import argparse
import masint
from prompt import prompt_template
import constants as constval

import logging

masint.api_url = "http://localhost:8000" 
#masint.api_url = "https://meta-llama--llama-3-2-3b-instruct.cray-lm.com"
logger = logging.getLogger(__name__)



def print_data(data):
    for item in data:
        print(item["input"])
        print(item["output"])
        print()


def get_data(training_data_file, dataset_size=1000):
    raw_data = get_raw_data(training_data_file)

    data = []

    for i in range(len(raw_data)):
        #print(f"{i} is {raw_data[i].keys()}")
        entry = prompt_template.format(
            source_code_path=raw_data[i]["source_code_path"],
            line_number=raw_data[i]["line_number"],
            code=get_source_code(raw_data[i]),
            bug_report_text=raw_data[i]["bug_report_text"])
        
        data.append(
            {
                "input": entry,
                "output": raw_data[i]["diff_text"] + "<|eot_id|>"
            }
        )
        print(f"\n Prompt contains \n {data[i]}")
    logger.info(f"Generated {len(data)} training samples")
    # random.seed(42)
    # random.shuffle(data)
    return data



def get_raw_data(training_data_file):
    with jsonlines.open(training_data_file) as reader:
        data = list(reader)

    return data


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

    llm = masint.SupermassiveIntelligence()
    train_response = llm.train(data, train_args={"max_steps": 200, "learning_rate": 3e-3})

    print(train_response)



# Entry point of the script
if __name__ == "__main__":
    main()
