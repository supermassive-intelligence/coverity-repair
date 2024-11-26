# Coverity Bug Fixing LLM Project

## Prerequisites
- Python 3.8+
- `venv` for virtual environment management

## Initial Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd duckpilot-coverity
```

### 2. Create and Activate Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

## Overview
This project provides a comprehensive pipeline for preparing, evaluating, visualizing, and fine-tuning a Large Language Model (LLM) to fix bugs based on Coverity bug reports.

## Project Structure
```
coverity/
│
├── dataprep/
│   └── create_formatted_data/
│       └── create_dataset_with_bug_diff_code.py
│
├── eval/
│   └── run.sh
│
├── visualize/
│   └── run.sh
│
└── train/
    └── run.sh
```

## Workflow Steps

### Step 1: Data Preparation
Prepare a dataset from Coverity bug descriptions, diffs, and source code.

We assume the file names have the format this-example-bug.txt and this-example-diff.txt. The source code directory contains the file in the same relative path as reflected in the "File" field of the this-example-bug.txt 

#### Usage
```bash
python dataprep/create_formatted_data/create_dataset_with_bug_diff_code.py \
  -b dataset/raw_data/bugs/gold-test-set \
  -c dataset/raw_data/code \
  -o dataset/tuning/inputs/gold-test-set.jsonlines
```

#### Parameters
- `-b, --bug-dir`: Path to raw bug reports
- `-c, --code-dir`: Path to source code
- `-o, --output-file`: Path for output dataset
- `-v, --verbose`: Enable verbose logging

### Step 2: Model Evaluation
Evaluate the LLM on the prepared dataset.

#### Usage
```bash
./eval/run.sh \
  -i dataset/tuning/inputs/gold-test-set.jsonlines \
  -o dataset/tuning/results/test-set-latest-eval.jsonlines \
  -m 9181192b57884a3fc6984a79e697c66305037d2ea9ee13b9ec58e2a8c0a6a227
```

#### Parameters
- `-i, --input`: Input dataset file
- `-o, --output`: Output results file
- `-m, --model`: Model hash to evaluate
- `-v, --verbose`: Enable verbose logging

### Step 3: Results Visualization
Generate a reference visualization of the diffs.

#### Usage
```bash
./visualize/run.sh \
  -i dataset/tuning/results/test-set-latest-eval.jsonlines \
  -o diff_output.txt
```

#### Parameters
- `-i, --input`: Input results file
- `-o, --output`: Output diff file
- `-v, --verbose`: Enable verbose logging

### Step 4: Model Fine-Tuning
Fine-tune a pre-trained LLM using the prepared dataset.

#### Usage
```bash
./train/run.sh \
  -i dataset/tuning/inputs/gold-test-set.jsonlines
```

#### Parameters
- `-i, --input`: Input dataset file for tuning
- `-v, --verbose`: Enable verbose logging

## Deactivating the Virtual Environment
When you're done working on the project, you can deactivate the virtual environment:
```bash
deactivate
```

## Default Model
By default, the evaluation uses `meta-llama/Meta-Llama-3.1-8B-Instruct`

## Contributing
1. Ensure you have the necessary permissions
2. Follow the step-by-step workflow
3. Test thoroughly before submitting changes

## License
[TBD]

## Contact
[sudnyadiamos@gmail.com]