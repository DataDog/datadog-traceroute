#!/bin/bash
# Validates traceroute JSON output for correctness
# Usage: validate_traceroute_json.sh <json_output>

set -euo pipefail

JSON_OUTPUT="$1"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track validation results
VALIDATION_PASSED=true

echo "Validating traceroute JSON output..."
echo

# Validation 1 & 2: For each traceroute run, check destination.ip_address matches last hop and last hop is reachable
echo "Checking traceroute runs..."
RUN_COUNT=$(echo "$JSON_OUTPUT" | jq '.traceroute.runs | length')
echo "  Found $RUN_COUNT traceroute run(s)"

for ((i=0; i<RUN_COUNT; i++)); do
    echo "  Run $((i+1)):"
    
    # Get last hop with non-null IP
    LAST_HOP_IP=$(echo "$JSON_OUTPUT" | jq -r ".traceroute.runs[$i].hops | map(select(.ip_address != null and .ip_address != \"\")) | last | .ip_address // \"null\"")
    LAST_HOP_REACHABLE=$(echo "$JSON_OUTPUT" | jq -r ".traceroute.runs[$i].hops | map(select(.ip_address != null and .ip_address != \"\")) | last | .reachable // false")
    DEST_IP=$(echo "$JSON_OUTPUT" | jq -r ".traceroute.runs[$i].destination.ip_address // \"null\"")
    
    # Validation 1: destination.ip_address equals last hop's ip_address
    if [ "$DEST_IP" = "$LAST_HOP_IP" ]; then
        echo -e "    ${GREEN}✓${NC} Destination IP ($DEST_IP) matches last hop IP"
    else
        echo -e "    ${RED}✗${NC} Destination IP ($DEST_IP) does NOT match last hop IP ($LAST_HOP_IP)"
        VALIDATION_PASSED=false
    fi
    
    # Validation 2: last hop is reachable
    if [ "$LAST_HOP_REACHABLE" = "true" ]; then
        echo -e "    ${GREEN}✓${NC} Last hop is reachable"
    else
        echo -e "    ${RED}✗${NC} Last hop is NOT reachable (reachable=$LAST_HOP_REACHABLE)"
        VALIDATION_PASSED=false
    fi
done

echo

# Validation 3 & 4: e2e_probe checks
echo "Checking e2e probe results..."
PACKETS_SENT=$(echo "$JSON_OUTPUT" | jq '.e2e_probe.packets_sent // 0')
PACKETS_RECEIVED=$(echo "$JSON_OUTPUT" | jq '.e2e_probe.packets_received // 0')
PACKET_LOSS=$(echo "$JSON_OUTPUT" | jq '.e2e_probe.packet_loss_percentage // 1')

echo "  Packets sent: $PACKETS_SENT"
echo "  Packets received: $PACKETS_RECEIVED"
echo "  Packet loss: $PACKET_LOSS"

# Validation 3: packets_sent equals packets_received
if [ "$PACKETS_SENT" -eq "$PACKETS_RECEIVED" ]; then
    echo -e "  ${GREEN}✓${NC} All packets received (sent=$PACKETS_SENT, received=$PACKETS_RECEIVED)"
else
    echo -e "  ${RED}✗${NC} Packet mismatch (sent=$PACKETS_SENT, received=$PACKETS_RECEIVED)"
    VALIDATION_PASSED=false
fi

# Validation 4: packet_loss_percentage is 0
if [ "$PACKET_LOSS" = "0" ]; then
    echo -e "  ${GREEN}✓${NC} No packet loss (0%)"
else
    echo -e "  ${RED}✗${NC} Packet loss detected ($PACKET_LOSS)"
    VALIDATION_PASSED=false
fi

echo

# Final result
if [ "$VALIDATION_PASSED" = true ]; then
    echo -e "${GREEN}All validations passed!${NC}"
    exit 0
else
    echo -e "${RED}Some validations failed!${NC}"
    exit 1
fi

