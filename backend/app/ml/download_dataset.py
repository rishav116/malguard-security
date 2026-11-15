import os
import urllib.request
import pandas as pd

DATASET_URL = "https://raw.githubusercontent.com/Anustup900/Automated-Malware-Analysis/master/dataset_malwares.csv"
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "dataset_malwares.csv")

def download_dataset():
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(OUTPUT_FILE):
        print(f"Dataset already exists at: {OUTPUT_FILE}")
    else:
        print(f"Downloading dataset from {DATASET_URL}...")
        req = urllib.request.Request(DATASET_URL, headers={"User-Agent": "MALGUARD-AI-Trainer/1.0"})
        with urllib.request.urlopen(req) as response:
            data = response.read()
        with open(OUTPUT_FILE, "wb") as f:
            f.write(data)
        print(f"Dataset successfully saved to: {OUTPUT_FILE}")

    # Verify and summarize
    df = pd.read_csv(OUTPUT_FILE)
    print(f"Verified dataset shape: {df.shape}")
    print("Class distribution:")
    print(df["Malware"].value_counts())
    print(f"Missing values: {df.isnull().sum().sum()}")
    print(f"Duplicates: {df.duplicated().sum()}")

if __name__ == "__main__":
    download_dataset()

