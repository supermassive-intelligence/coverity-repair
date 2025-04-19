import masint
import argparse
import logging
import re
import json


logger = logging.getLogger(__name__)

masint.api_url = "https://sudnya.cray-lm.com"
# masint.api_url = "http://localhost:8000"


def extract_c_functions_from_file(file_path):
    with open(file_path, "r") as file:
        source_code = file.read()

    functions = {}
    stack = []  # Stack to track nested levels
    current_pos = 0

    # First pass: Find potential function signatures
    signature_pattern = re.compile(
        r"""
        (^|\W)                    # Start of line or non-word char
        ([\w\s\*]+)               # Return type
        \s+(\w+)\s*               # Function name
        \(([^)]*)\)               # Parameters
        \s*{                      # Opening brace
        """,
        re.DOTALL | re.VERBOSE,
    )

    candidates = []
    for match in signature_pattern.finditer(source_code):
        func_name = match.group(3)
        start_pos = match.start() if match.group(1) == "" else match.start() + 1
        opening_brace_pos = match.end() - 1
        candidates.append((func_name, start_pos, opening_brace_pos))

    # Second pass: Properly pair opening and closing braces
    functions = {}
    for func_name, start_pos, opening_brace_pos in candidates:
        # Find the corresponding closing brace
        pos = opening_brace_pos
        brace_count = 1
        in_string = False
        in_char = False
        in_line_comment = False
        in_block_comment = False

        while pos < len(source_code) - 1 and brace_count > 0:
            pos += 1
            char = source_code[pos]
            next_char = source_code[pos + 1] if pos + 1 < len(source_code) else ""

            # Handle string literals
            if (
                char == '"'
                and not in_char
                and not in_line_comment
                and not in_block_comment
            ):
                # Check if escaped
                if pos > 0 and source_code[pos - 1] == "\\":
                    # Count backslashes before the quote
                    backslash_count = 1
                    bpos = pos - 2
                    while bpos >= 0 and source_code[bpos] == "\\":
                        backslash_count += 1
                        bpos -= 1
                    # If odd number of backslashes, quote is escaped
                    if backslash_count % 2 == 1:
                        continue
                in_string = not in_string
                continue

            # Handle character literals
            if (
                char == "'"
                and not in_string
                and not in_line_comment
                and not in_block_comment
            ):
                # Check if escaped
                if pos > 0 and source_code[pos - 1] == "\\":
                    # Count backslashes before the quote
                    backslash_count = 1
                    bpos = pos - 2
                    while bpos >= 0 and source_code[bpos] == "\\":
                        backslash_count += 1
                        bpos -= 1
                    # If odd number of backslashes, quote is escaped
                    if backslash_count % 2 == 1:
                        continue
                in_char = not in_char
                continue

            # Skip content in strings and character literals
            if in_string or in_char:
                continue

            # Handle comments
            if char == "/" and next_char == "/" and not in_block_comment:
                in_line_comment = True
                continue

            if in_line_comment and char == "\n":
                in_line_comment = False
                continue

            if char == "/" and next_char == "*" and not in_line_comment:
                in_block_comment = True
                pos += 1  # Skip the asterisk
                continue

            if char == "*" and next_char == "/" and in_block_comment:
                in_block_comment = False
                pos += 1  # Skip the slash
                continue

            # Skip content in comments
            if in_line_comment or in_block_comment:
                continue

            # Handle braces
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1

        # If we found matching closing brace
        if brace_count == 0:
            full_func = source_code[start_pos : pos + 1]
            functions[func_name] = full_func

    return functions


def create_null_check_function(src_code):
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer.<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += f"Inspect the following C function carefully and add null checks before dereferencing a pointer. {src_code}\n"
    # prompt_template += "Create samples for Null pointer dereference error. "
    prompt_template += "Only return the updated function. Do not explain."
    prompt_template += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"
    return prompt_template


def format_code_snippets(llm_responses):
    """
    Extract and format code snippets from LLM responses.

    Args:
        llm_responses: List of strings containing code snippets in markdown format

    Returns:
        List of cleaned code snippets
    """
    code_blocks = []
    combined_text = "\n".join(llm_responses)

    # Find all code blocks marked with ```c and ```
    pattern = r"```c\n(.*?)```"
    matches = re.findall(pattern, combined_text, re.DOTALL)

    for code_block in matches:
        code_blocks.append(code_block.strip())

    return code_blocks



def get_json_object_for_bug(fname, code, code_blocks):
    if not code_blocks:
        return False

    json_object = {
        "function_name": fname,
        "original_function": code,
        "fixed_function": code_blocks[0] if code_blocks else "",
    }
    return json_object


def write_to_json_file(fname, code, code_blocks):
    try:
        json_object = get_json_object_for_bug(fname, code, code_blocks)
        # Write the JSON object to a file
        with open(f"{fname}.json", "w") as file:
            json.dump(json_object, file, indent=4)
        return True
    except Exception as e:
        print(f"Error writing to file: {e}")
        return False


def write_to_file(fname, code, code_blocks):
    if len(code_blocks) <= 0:
        return
    with open(f"code_snippet_{fname}.c", "w") as file:
        file.write(f"Function name: {fname}")
        file.write(f"\nInput: \n{code}\n")
        file.write(f"\nOutput: \n{code_blocks[0]}")


def print_pretty_code(code_blocks):
    for i, code in enumerate(code_blocks):
        print(f"\n{'='*80}")
        print(code)


def normalize_string(s):
    # Replace all whitespace sequences with a single space
    s = " ".join(s.split())
    return s


def create_diff_prompt(original_code):
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer.<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += f"Write a coverity bug description about the null pointer dereference bug using the code in the value of {original_code}"
    prompt_template += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"
    return prompt_template


def create_bug_fix_prompt(original_code, fixed_code):
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer.<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += f"Generate a git diff between the {original_code} and {fixed_code}. Do not explain. Directly return the diff."
    prompt_template += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"
    return prompt_template

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

    logger.info(f"\nWriting eval results to {args.output}\n")

    functions = extract_c_functions_from_file(args.input)
    llm = masint.SupermassiveIntelligence()

    for name, original_code in functions.items():
        prompt = create_null_check_function(original_code)
        llm_response = llm.generate(prompts=[prompt], max_tokens=256)
        code_blocks = format_code_snippets(llm_response)
        if len(code_blocks) <= 0:
            continue
        # normalized_input = normalize_string(code)
        # normalized_output = normalize_string(code_blocks[0])

        # if normalized_input == normalized_output:
        #    print("Equal!")
        #    continue

        # Option 1: Write to files
        #write_to_json_file(name, code, code_blocks)
        write_to_file(name, original_code, code_blocks)
        bug_prompt = create_diff_prompt(original_code)
        bug_description = llm.generate(prompts=[bug_prompt], max_tokens=256)
        #print(normalize_string(bug_description[0]))

        bug_fix_prompt = create_bug_fix_prompt(original_code, code_blocks)
        fix_diff = llm.generate(prompts=[bug_fix_prompt], max_tokens=256)
        #print(normalize_string(fix_diff[0]))
        print(fix_diff)
        entry = {}
        entry["filename"] = name
        entry["original_code"] = original_code
        entry["fixed_code"] = code_blocks
        entry["bug_report"] = bug_description
        entry["diff"] = fix_diff

        print(entry)
        # Option 2: Print to console
        # print_pretty_code(code_blocks)


# Entry point of the script
if __name__ == "__main__":
    main()
