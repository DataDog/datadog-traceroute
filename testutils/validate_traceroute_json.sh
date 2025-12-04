#!/bin/bash
# Validates traceroute JSON output for correctness
# Usage: validate_traceroute_json.sh <json_output> [max_pkt_loss_pct] [expected_error_string]
#   json_output: JSON output from traceroute
#   max_pkt_loss_pct: Maximum packet loss percentage threshold (0.0-1.0), defaults to 0.0 (0% packet loss)
#   expected_error_string: Optional error string that must be present in the output (empty string means no check)
#                          If provided and found, all other validations are skipped

set -euo pipefail

JSON_OUTPUT="$1"
MAX_PKT_LOSS_PCT="${2:-0.9}"
EXPECTED_ERROR_STRING="${3:-}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track validation results
VALIDATION_PASSED=true

echo "Validating traceroute JSON output..."
echo

# Validation 1: Check if expected error string is present in output (if specified)
# If found, skip all other validations
if [ -n "$EXPECTED_ERROR_STRING" ]; then
    echo "Checking for expected error string in output..."
    if echo "$JSON_OUTPUT" | grep -qF "$EXPECTED_ERROR_STRING"; then
        echo -e "  ${GREEN}✓${NC} Expected error string found: \"$EXPECTED_ERROR_STRING\""
        echo
        echo -e "${GREEN}Error validation passed! Skipping other checks.${NC}"
        exit 0
    else
        echo -e "  ${RED}✗${NC} Expected error string NOT found: \"$EXPECTED_ERROR_STRING\""
        echo
        echo -e "${RED}Error validation failed!${NC}"
        exit 1
    fi
fi

# Validation 2 & 3: For each traceroute run, check destination.ip_address matches last hop and last hop is reachable
echo "Checking traceroute runs..."
RUN_COUNT=$(echo "$JSON_OUTPUT" | jq '.traceroute.runs | length')
echo "  Found $RUN_COUNT traceroute run(s)"

for ((i=0; i<RUN_COUNT; i++)); do
    echo "  Run $((i+1)):"

    # Get last hop with non-null IP
    LAST_HOP_IP=$(echo "$JSON_OUTPUT" | jq -r ".traceroute.runs[$i].hops | map(select(.ip_address != null and .ip_address != \"\")) | last | .ip_address // \"null\"")
    LAST_HOP_REACHABLE=$(echo "$JSON_OUTPUT" | jq -r ".traceroute.runs[$i].hops | map(select(.ip_address != null and .ip_address != \"\")) | last | .reachable // false")
    DEST_IP=$(echo "$JSON_OUTPUT" | jq -r ".traceroute.runs[$i].destination.ip_address // \"null\"")

    # Validation 2: destination.ip_address equals last hop's ip_address
    if [ "$DEST_IP" = "$LAST_HOP_IP" ]; then
        echo -e "    ${GREEN}✓${NC} Destination IP ($DEST_IP) matches last hop IP"
    else
        echo -e "    ${RED}✗${NC} Destination IP ($DEST_IP) does NOT match last hop IP ($LAST_HOP_IP)"
        VALIDATION_PASSED=false
    fi

    # Validation 3: last hop is reachable
    if [ "$LAST_HOP_REACHABLE" = "true" ]; then
        echo -e "    ${GREEN}✓${NC} Last hop is reachable"
    else
        echo -e "    ${RED}✗${NC} Last hop is NOT reachable (reachable=$LAST_HOP_REACHABLE)"
        VALIDATION_PASSED=false
    fi
done

echo

# Validation 4 & 5: e2e_probe checks
echo "Checking e2e probe results..."
PACKETS_SENT=$(echo "$JSON_OUTPUT" | jq '.e2e_probe.packets_sent // 0')
PACKETS_RECEIVED=$(echo "$JSON_OUTPUT" | jq '.e2e_probe.packets_received // 0')
PACKET_LOSS=$(echo "$JSON_OUTPUT" | jq '.e2e_probe.packet_loss_percentage // 1')

echo "  Packets sent: $PACKETS_SENT"
echo "  Packets received: $PACKETS_RECEIVED"
echo "  Packet loss: $PACKET_LOSS"

# Validation 4: packets_sent is >= 1
if [ "$PACKETS_SENT" -ge 1 ]; then
    echo -e "  ${GREEN}✓${NC} Packets sent is >= 1 (sent=$PACKETS_SENT)"
else
    echo -e "  ${RED}✗${NC} Packets sent is < 1 (sent=$PACKETS_SENT)"
    VALIDATION_PASSED=false
fi

# Validation 5: packet_loss_percentage is <= max_pkt_loss_pct
# note, packet_loss_percentage is float between 0 and 1
if awk -v pl="$PACKET_LOSS" -v max="$MAX_PKT_LOSS_PCT" 'BEGIN {exit !(pl <= max)}'; then
    echo -e "  ${GREEN}✓${NC} Packet loss percentage is <= threshold ($PACKET_LOSS <= $MAX_PKT_LOSS_PCT)"
else
    echo -e "  ${RED}✗${NC} Packet loss percentage is > threshold ($PACKET_LOSS > $MAX_PKT_LOSS_PCT)"
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
