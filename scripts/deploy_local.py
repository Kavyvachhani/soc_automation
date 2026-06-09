import os
import shutil
import subprocess
import zipfile
from pathlib import Path
import boto3

REPO_ROOT = Path(__file__).resolve().parent.parent
LAMBDA_DIR = REPO_ROOT / "lambda"
BUILD_DIR = REPO_ROOT / "build_lambda"

FUNCTIONS = ["offer_processor", "signed_processor", "approval_handler"]

def main():
    print("Starting deployment of Lambda functions...")

    # Set AWS region for boto3 if not present
    if "AWS_DEFAULT_REGION" not in os.environ:
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    # Clean and recreate build directory
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir()

    for func in FUNCTIONS:
        func_build_dir = BUILD_DIR / func
        func_build_dir.mkdir()

        print(f"\n--- Building package for {func} ---")

        import sys
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "-r", str(LAMBDA_DIR / "requirements.txt"), "-t", str(func_build_dir)],
            check=True
        )

        # Copy source code
        print(f"Copying source file lambda/{func}.py...")
        shutil.copy(LAMBDA_DIR / f"{func}.py", func_build_dir)

        # Copy templates if they exist
        templates_src = LAMBDA_DIR / "templates"
        if templates_src.exists():
            print("Copying templates...")
            shutil.copytree(templates_src, func_build_dir / "templates")

        # Create zip file
        zip_path = BUILD_DIR / f"{func}.zip"
        print(f"Creating zip archive at {zip_path.name}...")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(func_build_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(func_build_dir)
                    zipf.write(file_path, arcname)

        # Deploy to AWS Lambda
        function_name = f"attest-{func.replace('_', '-')}"
        print(f"Deploying to AWS Lambda function: {function_name}...")
        lambda_client = boto3.client("lambda", region_name="us-east-1")

        with open(zip_path, 'rb') as f:
            zip_bytes = f.read()

        response = lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_bytes
        )
        print(f"Deployment successful! Version: {response['Version']}, CodeSize: {response['CodeSize']} bytes.")

    print("\nAll Lambda functions deployed successfully!")

if __name__ == "__main__":
    main()
