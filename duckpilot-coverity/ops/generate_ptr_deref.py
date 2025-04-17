import masint
import argparse
import logging
import re
import difflib

logger = logging.getLogger(__name__)

source_code = """
static bool aldebaran_is_mode2_default(struct amdgpu_reset_control *reset_ctl)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;

	if ((amdgpu_ip_version(adev, MP1_HWIP, 0) == IP_VERSION(13, 0, 2) &&
	     adev->gmc.xgmi.connected_to_cpu))
		return true;

	return false;
}
"""

def b():
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer.<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += f"Inspect the following C function carefully and remove all the null checks before dereferencing a pointer. {source_code}"
    prompt_template += "Create samples for Null pointer dereference error. Only return the updated function. Do not explain."
    prompt_template += "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"
    return prompt_template

masint.api_url = "https://llama3btensorwave.cray-lm.com/"
#masint.api_url = "http://localhost:8000" 

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


def build_prompt(src_code):
    prompt_template = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>"
    prompt_template += "Cutting Knowledge Date: December 2023\n"
    prompt_template += "Today Date: March 4 2025\n"
    prompt_template += "You are an expert linux driver developer.<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    prompt_template += f"Inspect the following C function carefully and remove all the null checks before dereferencing a pointer. {src_code}\n"
    prompt_template += "Create samples for Null pointer dereference error. Only return the updated function. Do not explain."
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

    for name, code in functions.items():
        prompt = build_prompt(code)
        print(len(prompt))
        print(prompt)

        response = llm.generate(prompts=[prompt], max_tokens=256)
        print(response)


# Entry point of the script
if __name__ == "__main__":
    main()
