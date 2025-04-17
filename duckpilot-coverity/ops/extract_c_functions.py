import re
import argparse
import logging
logger = logging.getLogger(__name__)

import re
import re

import re

def extract_c_functions_from_file(file_path):
    with open(file_path, 'r') as file:
        source_code = file.read()

    # Match function signature + body
    pattern = re.compile(
        r"""
        ([\w\s\*\(\)]+?)          # return type and maybe part of the name
        \s+(\w+)\s*               # function name
        \(([^)]*)\)               # parameters
        \s*\{                     # open brace
        (.*?)                     # function body (naive match)
        \}                        # closing brace
        """,
        re.DOTALL | re.VERBOSE,
    )

    functions = {}
    for match in pattern.finditer(source_code):
        func_name = match.group(2)
        full_func = source_code[match.start():match.end()]  # exact source slice
        functions[func_name] = full_func

    return functions



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
        default="/Users/sudnya/checkout/smi/coverity-repair/duckpilot-coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c",
        help="Path to the input source file to extract functions from",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="/Users/sudnya/checkout/smi/coverity-repair/duckpilot-coverity/extracted_functions.json",
        help="Name of the file to write eval results to",
    )

    args = parser.parse_args()

    # Set up logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    logger.info(f"\nLoading data from {args.input}\n")

    input_path = args.input

    functions = extract_c_functions_from_file(input_path)
    for name, code in functions.items():
        print(f"{name}\n{'-'*40}")
        print(code)
        print()

if __name__ == "__main__":
    main()
