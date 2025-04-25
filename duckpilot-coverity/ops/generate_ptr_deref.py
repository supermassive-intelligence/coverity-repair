import masint
import argparse
import logging
import re
import json


logger = logging.getLogger(__name__)


masint.api_url = "https://sudnya.cray-lm.com"
# masint.api_url = "http://localhost:8000"

import os
from pathlib import Path
from typing import Union

def trim_path(path: Union[str, Path], base: Union[str, Path]) -> str:
    """
    Return path relative to base. If `path` is not under `base`, return it unchanged.

    :param path: Absolute file path to trim
    :param base:   Base directory prefix to remove
    :return:       Trimmed (relative) path as a string
    """
    path = Path(path)
    base = Path(base)

    try:
        # Use Path.relative_to if it’s truly a subpath
        rel = path.relative_to(base)
    except ValueError:
        # Not under base → fall back to os.path.relpath (could produce '..' segments)
        rel = Path(os.path.relpath(path, base))
    return str(rel)


def create_git_diff(original_code, fixed_code, original_file="original.c", fixed_file="fixed.c"):
    """
    Create a git-style diff between original_code and fixed_code.
    
    Args:
        original_code (str): The original code with issues
        fixed_code (str): The fixed code
        original_file (str): Name to use for the original file in the diff
        fixed_file (str): Name to use for the fixed file in the diff
        
    Returns:
        str: A git-style diff output
    """
    # Split the code into lines
    original_lines = original_code.splitlines()
    fixed_lines = fixed_code.splitlines()
    
    # Initialize variables
    diff_output = []
    diff_output.append(f"diff --git a/{original_file} b/{fixed_file}")
    diff_output.append(f"--- a/{original_file}")
    diff_output.append(f"+++ b/{fixed_file}")
    
    # Find the differences
    i, j = 0, 0
    context_lines = 3  # Number of context lines before and after changes
    
    # Track if we're in a diff block
    in_diff_block = False
    diff_start_i = 0
    diff_start_j = 0
    
    while i < len(original_lines) and j < len(fixed_lines):
        # If lines are the same, move forward in both files
        if original_lines[i] == fixed_lines[j]:
            # If we were in a diff block, output the diff
            if in_diff_block:
                # Calculate line numbers for the hunk header
                orig_start = diff_start_i + 1
                orig_count = i - diff_start_i
                fixed_start = diff_start_j + 1
                fixed_count = j - diff_start_j
                
                # Add the hunk header
                diff_output.append(f"@@ -{orig_start},{orig_count} +{fixed_start},{fixed_count} @@")
                
                # Add the lines with appropriate prefix
                for k in range(diff_start_i, i):
                    diff_output.append(f"-{original_lines[k]}")
                for k in range(diff_start_j, j):
                    diff_output.append(f"+{fixed_lines[k]}")
                
                in_diff_block = False
            
            i += 1
            j += 1
        else:
            # We found a difference
            if not in_diff_block:
                in_diff_block = True
                diff_start_i = max(0, i - context_lines)
                diff_start_j = max(0, j - context_lines)
                
                # Add context lines
                for k in range(diff_start_i, i):
                    if k < len(original_lines) and k < len(fixed_lines) and original_lines[k] == fixed_lines[k]:
                        diff_output.append(f" {original_lines[k]}")
            
            # Try to find where they align again
            orig_temp = i
            fixed_temp = j
            found_sync = False
            
            # Simple approach: look ahead a few lines to find synchronization point
            for look_ahead in range(1, min(8, len(original_lines) - i, len(fixed_lines) - j)):
                if i + look_ahead < len(original_lines) and j + look_ahead < len(fixed_lines):
                    if original_lines[i + look_ahead] == fixed_lines[j + look_ahead]:
                        # We found a sync point
                        for k in range(i, i + look_ahead):
                            diff_output.append(f"-{original_lines[k]}")
                        for k in range(j, j + look_ahead):
                            diff_output.append(f"+{fixed_lines[k]}")
                        i += look_ahead
                        j += look_ahead
                        found_sync = True
                        in_diff_block = False
                        break
            
            if not found_sync:
                # If we can't find a sync point, just advance in both files
                diff_output.append(f"-{original_lines[i]}")
                diff_output.append(f"+{fixed_lines[j]}")
                i += 1
                j += 1
    
    # Handle any remaining lines
    while i < len(original_lines):
        diff_output.append(f"-{original_lines[i]}")
        i += 1
    
    while j < len(fixed_lines):
        diff_output.append(f"+{fixed_lines[j]}")
        j += 1
    
    return "\n".join(diff_output)



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



def print_c_source_code(code_lines):
    for line in code_lines:
        # Remove escape sequences and split by line
        for subline in line.split("\\n"):
            formatted_line = subline.replace("\\t", "\t")
            print(formatted_line)


def create_ptr_dereference_function(src_code):
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer.<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += "Create a C function that dereferences a pointer and uses that value in the function."
    prompt_template += "The code should be realistic and have signature like the function below. "
    prompt_template += f"Confirm that there is a point dereference error in this function, but no other bugs.{src_code}\n"
    prompt_template += "Only return the function. Do not explain."
    prompt_template += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"
    return prompt_template


def format_code_snippets(llm_responses):
    """
    Extract and format code snippets from LLM responses.
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


def create_coverity_bug(original_code, input_src_code_file):
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer. Do not use any formatting, bullet points, bold text, or "
    prompt_template += "structured sections in your response. Provide the coverity bug description as plain text only."
    prompt_template += "<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += "Write a coverity bug description about the null pointer dereference in the following code "
    prompt_template += f"and recommend how to fix it \n {original_code}\n"
    prompt_template += f"The source file is {input_src_code_file}."
    prompt_template += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"
    return prompt_template


def create_bug_fix_prompt(original_code, bug_description):
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer.<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += f"Here is the source code {original_code}. Here is a bug description {bug_description}."
    prompt_template += "Update the source code by adding null pointer checks before dereferencing the pointer."
    prompt_template += "Do not change anything else. Do not explain your answer. Return the updated source code."
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
    input_src_code_file = args.input

    # Set up logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    logger.info(f"\nLoading data from {input_src_code_file}\n")

    logger.info(f"\nWriting eval results to {args.output}\n")

    functions = extract_c_functions_from_file(input_src_code_file)
    llm = masint.SupermassiveIntelligence()

    for name, original_code in functions.items():

        # 1. Create a function with pointer dereference error
        create_ptr_deref_prompt = create_ptr_dereference_function(original_code)
        logger.debug(f"\nPROMPT:\nCreate null ptr dereference function: \n{create_ptr_deref_prompt}\n\n")
        llm_response = llm.generate(prompts=[create_ptr_deref_prompt], max_tokens=256)
        code_blocks = format_code_snippets(llm_response)
        if len(code_blocks) <= 0: continue
        training_sample = code_blocks[0]
        logger.info(f"\n\nLLM generated null ptr dereference function: \n {training_sample}")

        # 2. Create a coverity bug description
        #write_to_json_file(name, code, code_blocks)
        #write_to_file(name, original_code, code_blocks)
        bug_prompt = create_coverity_bug(training_sample, trim_path(path=input_src_code_file, base='/Users/sudnya/checkout/smi/coverity-repair/duckpilot-coverity/dataset/raw_data/code/'))
        logger.debug(f"\nPROMPT:\n Bug description: \n{bug_prompt}\n\n")
        bug_description = llm.generate(prompts=[bug_prompt], max_tokens=256)
        logger.info(f"\n\nLLM generated bug description: \n{normalize_string(bug_description[0])}\n\n")

        bug_fix_prompt = create_bug_fix_prompt(training_sample, bug_description)
        logger.debug(f"\nPROMPT:\n Bug fix: \n{bug_fix_prompt}\n\n")
        fixed_code_response = llm.generate(prompts=[bug_fix_prompt], max_tokens=256)
        fixed_code_sample = format_code_snippets(fixed_code_response)[0]
        logger.info(f"\n\nLLM generated bug fix: \n {fixed_code_sample}")



        diff_string = create_git_diff(training_sample, fixed_code_sample)
        logger.info(f"\nDiff: \n\n{diff_string}")


        entry = {}
        entry["filename"] = name
        entry["inspiration_code"] = original_code
        entry["buggy_code"] = code_blocks
        entry["fixed_code"] = fixed_code_sample
        entry["bug_report"] = bug_description
        entry["diff"] = diff_string

        #print(entry)
        # Option 2: Print to console
        # print_pretty_code(code_blocks)'''


# Entry point of the script
if __name__ == "__main__":
    main()
