#!/usr/bin/env python3
"""
Build and deploy all 3 Lambda functions directly from local machine.
Equivalent to what deploy-lambdas.yml does in GitHub Actions.
Run: python3 scripts/deploy_lambdas_direct.py
"""
import boto3, zipfile, io, os, subprocess, sys, tempfile, shutil
from pathlib import Path

REGION   = "us-east-1"
ROOT     = Path(__file__).parent.parent
LAMBDA_DIR = ROOT / "lambda"
REQS_FILE  = LAMBDA_DIR / "requirements.txt"

FUNCTIONS = {
    "offer_processor":  "attest-offer-processor",
    "signed_processor": "attest-signed-processor",
    "approval_handler": "attest-approval-handler",
}

client = boto3.client("lambda", region_name=REGION)

for src_name, fn_name in FUNCTIONS.items():
    print(f"\n{'='*60}")
    print(f"Deploying {fn_name} ...")
    build_dir = Path(tempfile.mkdtemp())

    try:
        # Install dependencies
        print(f"  Installing dependencies ...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q",
             "-r", str(REQS_FILE), "-t", str(build_dir)],
            check=True
        )

        # Copy source file
        src_file = LAMBDA_DIR / f"{src_name}.py"
        shutil.copy(src_file, build_dir / f"{src_name}.py")

        # Copy templates dir
        templates_src = LAMBDA_DIR / "templates"
        if templates_src.exists():
            shutil.copytree(templates_src, build_dir / "templates")

        # Build zip in memory
        print(f"  Building zip ...")
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(build_dir):
                # Skip __pycache__
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for file in files:
                    if file.endswith(".pyc"):
                        continue
                    full_path = Path(root) / file
                    arc_name  = full_path.relative_to(build_dir)
                    zf.write(full_path, arc_name)

        zip_bytes = zip_buf.getvalue()
        print(f"  Zip size: {len(zip_bytes)/1024/1024:.1f} MB")

        # Upload
        print(f"  Uploading to Lambda: {fn_name} ...")
        resp = client.update_function_code(
            FunctionName=fn_name,
            ZipFile=zip_bytes,
        )
        print(f"  State: {resp.get('State')}  CodeSize: {resp.get('CodeSize'):,} bytes")

        # Wait for update
        waiter = client.get_waiter("function_updated")
        waiter.wait(FunctionName=fn_name)
        print(f"  ✅  {fn_name} deployed and active")

    except Exception as e:
        print(f"  ❌  Failed: {e}")
        import traceback; traceback.print_exc()
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)

print("\nAll deployments complete.")
