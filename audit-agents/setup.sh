#!/bin/bash
# =============================================================
# Web3 Bug Bounty Audit Agents - Setup Script
# =============================================================

set -e

echo "========================================="
echo "  Web3 Audit Agents - Setup"
echo "========================================="

# 1. Install Foundry
echo "[1/5] Installing Foundry..."
if ! command -v forge &> /dev/null; then
    curl -L https://foundry.paradigm.xyz | bash
    export PATH="$HOME/.foundry/bin:$PATH"
    foundryup
    echo "  Foundry installed."
else
    echo "  Foundry already installed: $(forge --version)"
fi

# 2. Python virtual environment
echo "[2/5] Setting up Python environment..."
python -m venv .venv
source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "  Python environment ready."

# 3. Install solc
echo "[3/5] Installing solc via solc-select..."
pip install solc-select
solc-select install 0.8.26
solc-select use 0.8.26
echo "  solc 0.8.26 installed."

# 4. Initialize Foundry project for PoC testing
echo "[4/5] Initializing Foundry workspace..."
if [ ! -d "foundry-workspace" ]; then
    mkdir foundry-workspace && cd foundry-workspace
    forge init --no-commit
    # Install OpenZeppelin for testing
    forge install OpenZeppelin/openzeppelin-contracts --no-commit
    cd ..
    echo "  Foundry workspace ready."
else
    echo "  Foundry workspace already exists."
fi

# 5. Create .env template
echo "[5/5] Creating .env template..."
if [ ! -f ".env" ]; then
    cat > .env << 'ENVEOF'
# RPC URLs for forking mainnet
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
BSC_RPC_URL=https://bsc-dataseed.binance.org
POLYGON_RPC_URL=https://polygon-rpc.com
ARBITRUM_RPC_URL=https://arb1.arbitrum.io/rpc
# Etherscan API keys for contract verification/download
ETHERSCAN_API_KEY=YOUR_KEY
# Output
REPORTS_DIR=./reports
ENVEOF
    echo "  .env template created. Fill in your API keys."
else
    echo "  .env already exists."
fi

echo ""
echo "========================================="
echo "  Setup complete!"
echo "  Activate env: source .venv/Scripts/activate"
echo "  Run audit:    python audit.py <contract.sol>"
echo "========================================="
