#!/bin/bash
# FortifyOne Complete Test Run
# This tests all modules end-to-end

echo "╔══════════════════════════════════════════╗"
echo "║   FortifyOne - Complete Test Suite       ║"
echo "║   TrinTech Digital Defense              ║"
echo "╚══════════════════════════════════════════╝"
echo ""

PYTHON_CMD="python3"
FOR_CMD="$PYTHON_CMD /root/fortifyone/main.py"

# Test 1: System Info
echo "=== TEST 1: System Information ==="
$FOR_CMD info
echo ""

# Test 2: Create new audit
echo "=== TEST 2: Create New Audit ==="
$FOR_CMD new --client "Demo Test Corp" --domain "example.com" --ip "93.184.216.34"
echo ""

# Test 3: List audits
echo "=== TEST 3: List Audits ==="
$FOR_CMD list
echo ""

# Find the audit file
AUDIT_FILE=$(ls -t /root/fortifyone/data/Demo_Test_Corp_*.json | head -1)
echo "Using audit file: $AUDIT_FILE"
echo ""

# Test 4: Run external scan
echo "=== TEST 4: External Scan ==="
$FOR_CMD run --module external --file "$AUDIT_FILE"
echo ""

# Find updated file
UPDATED_FILE=$(ls -t /root/fortifyone/data/Demo_Test_Corp_updated_*.json | head -1)
if [ -z "$UPDATED_FILE" ]; then
    UPDATED_FILE=$(ls -t /root/fortifyone/data/Demo_Test_Corp_*.json | head -1)
fi
echo "Using updated file: $UPDATED_FILE"
echo ""

# Test 5: Run policy engine
echo "=== TEST 5: Policy Engine ==="
echo "Note: This will require interactive input. Press Ctrl+C to skip."
$FOR_CMD run --module policy --file "$UPDATED_FILE" || echo "(Skipped or completed)"
echo ""

# Test 6: Generate report
echo "=== TEST 6: Generate Report ==="
FINAL_FILE=$(ls -t /root/fortifyone/data/Demo_Test_Corp_*.json | head -1)
$FOR_CMD report --file "$FINAL_FILE"
echo ""

# Test 7: Show results
echo "=== TEST 7: Results ==="
echo "Output files:"
find /root/fortifyone/output -type f 2>/dev/null | head -10
echo ""
echo "Audit data files:"
ls -la /root/fortifyone/data/
echo ""
echo "=== Test Complete ==="
