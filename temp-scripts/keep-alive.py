import time
import requests

# Define the URL of the endpoint
URL = "https://smi-workspace--cray-nvidia-llama-3-2-3b-instruct-fastapi-app.modal.run/v1/health"

# Function to make a GET request
def hit_endpoint():
    try:
        response = requests.get(URL)
        if response.status_code == 200:
            print(f"Success: {response.json()}")  # Assuming the response is JSON
        else:
            print(f"Failed with status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"An error occurred: {e}")

# Main loop to hit the endpoint every 2 minutes
def main():
    while True:
        print("Hitting the endpoint...")
        hit_endpoint()
        print("Waiting for 2 minutes...")
        time.sleep(120)  # 2 minutes in seconds

if __name__ == "__main__":
    main()

