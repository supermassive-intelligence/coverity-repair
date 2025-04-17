import json
import argparse

def main():
    parser = argparse.ArgumentParser(description="Pretty-print JSON objects from a .jsonlines file.")
    parser.add_argument("-i", "--input", type=str, help="Path to the .jsonlines file")

    args = parser.parse_args()

    try:
        with open(args.input, "r") as f:
            data = json.load(f)
            if not isinstance(data, list):
                print("Expected a JSON array of objects.")
                return
            for obj in data:
                print(f'Filename: {obj.get("filename")}')
                print(f'Function: {obj.get("functionname")}')
                print("Code:\n")
                print(obj.get("code"))
                print("\n" + "="*40 + "\n")

    except FileNotFoundError:
        print(f"File not found: {args.filepath}")
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")

if __name__ == "__main__":
    main()

