import os
import shutil
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_REPOS_DIR = os.path.join(BASE_DIR, "sample-repos")
WORKSPACES_DIR = os.path.join(BASE_DIR, "workspaces")

VULN_REPO_MAP = {
    "GCAS-E2E-001": "gcas-agentic-e2e-test-repo",
    "GCAS-E2E-002": "gcas-agentic-e2e-test-repo",
    "GCAS-E2E-003": "gcas-agentic-e2e-test-repo",
    "GCAS-E2E-004": "gcas-agentic-e2e-test-repo",
    "GCAS-E2E-005": "gcas-agentic-e2e-test-repo",
    "GCAS-E2E-006": "gcas-agentic-e2e-test-repo",
    "VUL-POC-001": "payments-api",
    "VUL-POC-002": "customer-service",
    "VUL-POC-003": "inventory-manager",
    "VUL-POC-004": "identity-provider",
    "VUL-POC-005": "payments-api",
    "VUL-POC-006": "payments-api",
    "VUL-POC-007": "payments-api",
    "VUL-POC-008": "customer-service",
    "VUL-POC-009": "customer-service",
    "VUL-POC-010": "inventory-manager",
    "VUL-POC-011": "storefront-api",
}

print(f"Setting up workspaces in {WORKSPACES_DIR}...")

for vuln_id, repo_name in VULN_REPO_MAP.items():
    src_repo = os.path.join(SAMPLE_REPOS_DIR, repo_name)
    target_workspace = os.path.join(WORKSPACES_DIR, vuln_id, "repository")
    
    if os.path.exists(target_workspace):
        print(f"[{vuln_id}] Workspace already exists at {target_workspace}")
        continue
    
    if not os.path.exists(src_repo):
        print(f"[{vuln_id}] Warning: Sample repo missing at {src_repo}")
        continue
        
    print(f"[{vuln_id}] Copying {repo_name} -> {target_workspace}")
    shutil.copytree(src_repo, target_workspace, dirs_exist_ok=True)
    
    # Check out remediation branch if git is present
    try:
        branch_name = f"remediation/{vuln_id.lower()}"
        subprocess.run(["git", "checkout", "-B", branch_name], cwd=target_workspace, capture_output=True)
    except Exception as e:
        print(f"[{vuln_id}] Git branch creation warning: {e}")

print("Workspace setup complete!")
