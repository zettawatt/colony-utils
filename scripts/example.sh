#!/bin/bash

# Colony Daemon Async API Test Script
#
# This script demonstrates the new JWT authentication system and tests both
# public and protected endpoints of the colony-daemon REST API.
#
# Usage:
#   ./example.sh                           # Uses default password 'password'
#   KEYSTORE_PASSWORD=mypass ./example.sh  # Uses custom password
#
# Prerequisites:
#   - colonyd running on localhost:3000
#   - jq installed for JSON parsing
#   - Valid keystore password

BASE_URL="http://localhost:3000"

# Default keystore password (can be overridden with environment variable)
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-password}"

echo "🚀 Testing Colony Daemon Async REST API with JWT Authentication"
echo "================================================================"
echo "🔑 Using keystore password: ${KEYSTORE_PASSWORD:0:3}***"
echo ""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "❌ Error: jq is required but not installed."
    echo "   Please install jq: https://stedolan.github.io/jq/download/"
    exit 1
fi

# Function to poll job status until completion
# Job status and result endpoints are public (no auth required)
poll_job() {
    local job_id=$1
    local operation_name=$2
    echo "⏳ Polling job $job_id for $operation_name..."

    while true; do
        response=$(curl -s -X GET "$BASE_URL/colony-0/jobs/$job_id")

        status=$(echo $response | jq -r '.job.status')
        progress=$(echo $response | jq -r '.job.progress // 0')
        message=$(echo $response | jq -r '.job.message // ""')

        echo "   Status: $status, Progress: $(printf "%.1f" $progress), Message: $message"

        if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
            break
        fi

        sleep 2
    done

    if [ "$status" = "completed" ]; then
        echo "✅ $operation_name completed successfully!"
        # Get the result (also public endpoint)
        echo "📋 Getting result for $operation_name..."
        curl -s -X GET "$BASE_URL/colony-0/jobs/$job_id/result" | jq
    else
        echo "❌ $operation_name failed!"
        echo $response | jq
    fi
}

# Get JWT token with keystore password
echo "📝 Getting JWT token..."
echo "🔐 Using keystore password: ${KEYSTORE_PASSWORD:0:3}***"

TOKEN_RESPONSE=$(curl -s -X POST $BASE_URL/colony-auth/token \
  -H "Content-Type: application/json" \
  -d "{\"password\": \"$KEYSTORE_PASSWORD\"}")

# Check if the request was successful
if echo "$TOKEN_RESPONSE" | jq -e '.token' > /dev/null 2>&1; then
    TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
    EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')
    echo "✅ Token obtained: ${TOKEN:0:20}..."
    echo "⏰ Token expires in: ${EXPIRES_IN} seconds"
else
    echo "❌ Failed to get JWT token"
    echo "Response: $TOKEN_RESPONSE"
    echo ""
    echo "💡 Tip: Make sure the colony-daemon is running and the keystore password is correct."
    echo "   You can set the password with: export KEYSTORE_PASSWORD='your_password'"
    exit 1
fi

# Health check (PUBLIC endpoint - no auth required)
echo -e "\n🏥 Testing health check (public endpoint)..."
curl -s -X GET $BASE_URL/colony-health | jq

# Test async cache refresh (PUBLIC endpoint - no auth required)
echo -e "\n🔄 Testing async cache refresh (public endpoint)..."
cache_response=$(curl -s -X POST $BASE_URL/colony-0/jobs/cache/refresh)
echo $cache_response | jq
cache_job_id=$(echo $cache_response | jq -r '.job_id')

if [ "$cache_job_id" != "null" ] && [ ! -z "$cache_job_id" ]; then
    poll_job $cache_job_id "Cache Refresh"
fi

# Test async refresh pod references with depth (PUBLIC endpoint - no auth required)
echo -e "\n📋 Testing async refresh pod references (depth 2, public endpoint)..."
refresh_response=$(curl -s -X POST $BASE_URL/colony-0/jobs/cache/refresh/2)
echo $refresh_response | jq
refresh_job_id=$(echo $refresh_response | jq -r '.job_id')

if [ "$refresh_job_id" != "null" ] && [ ! -z "$refresh_job_id" ]; then
   poll_job $refresh_job_id "Refresh Pod References"
fi

# Add a pod (PROTECTED endpoint - requires auth)
echo -e "\n➕ Testing add pod (protected endpoint)..."
POD_RESPONSE=$(curl -s -X POST $BASE_URL/colony-0/pods \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-pod-'$(date +%s)'"
  }')
echo $POD_RESPONSE | jq
POD_ADDRESS=$(echo $POD_RESPONSE | jq -r '.address')

# Test subject data operations (if we have a pod ID)
if [ "$POD_ADDRESS" != "null" ] && [ ! -z "$POD_ADDRESS" ]; then
    SUBJECT_ADDRESS=c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59
    echo -e "\n💾 Testing put subject data (protected endpoint)..."
    put_response=$(curl -s -X PUT $BASE_URL/colony-0/pods/$POD_ADDRESS/c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59 \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "@context": {"schema": "http://schema.org/"},
        "@type": "schema:MediaObject",
        "@id": "ant://c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59",
        "schema:name": "BegBlag.mp3",
        "schema:description": "Beg Blag and Steal",
        "schema:contentSize": "4MB"
      }')
    echo $put_response | jq

    echo -e "\n📖 Testing async get subject data (public endpoint)..."
    subject_response=$(curl -s -X POST $BASE_URL/colony-0/jobs/search/subject/$SUBJECT_ADDRESS)
    echo $subject_response | jq
    subject_job_id=$(echo $subject_response | jq -r '.job_id')

    if [ "$subject_job_id" != "null" ] && [ ! -z "$subject_job_id" ]; then
        poll_job $subject_job_id "Get Subject Data"
    fi

    echo -e "\n🔗 Testing add pod reference (protected endpoint)..."
    POD_REF_ADDRESS=8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e
    pod_ref_response=$(curl -s -X POST $BASE_URL/colony-0/pods/$POD_ADDRESS/pod_ref \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "pod_ref": "8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e"
      }')
    echo $pod_ref_response | jq

    # echo -e "\n🗑️ Testing remove pod reference (protected endpoint)..."
    # curl -s -X DELETE "$BASE_URL/colony-0/pods/$POD_ADDRESS/pod_ref?pod_ref=test-reference-address" \
    #   -H "Authorization: Bearer $TOKEN" | jq
fi

# Test async search (PUBLIC endpoint - no auth required)
echo -e "\n🔍 Testing async search (public endpoint)..."
search_response=$(curl -s -X POST "$BASE_URL/colony-0/jobs/search" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "text",
    "text": "beg",
    "limit": 50
  }')
echo $search_response | jq
search_job_id=$(echo $search_response | jq -r '.job_id')

if [ "$search_job_id" != "null" ] && [ ! -z "$search_job_id" ]; then
    poll_job $search_job_id "Search"
fi

# Test async upload all pods (PROTECTED endpoint - requires auth)
echo -e "\n⬆️ Testing async upload all pods (protected endpoint)..."
upload_response=$(curl -s -X POST $BASE_URL/colony-0/jobs/cache/upload \
  -H "Authorization: Bearer $TOKEN")
echo $upload_response | jq
upload_job_id=$(echo $upload_response | jq -r '.job_id')

if [ "$upload_job_id" != "null" ] && [ ! -z "$upload_job_id" ]; then
    poll_job $upload_job_id "Upload All Pods"
fi

# Demonstrate checking job status for a non-existent job (PUBLIC endpoint - no auth required)
echo -e "\n🔍 Testing job status for non-existent job (public endpoint)..."
curl -s -X GET "$BASE_URL/colony-0/jobs/non-existent-job-id" | jq

# Test listing pods (PROTECTED endpoint - requires auth)
echo -e "\n📦 Testing list my pods (protected endpoint)..."
list_response=$(curl -s -X GET "$BASE_URL/colony-0/pods" \
  -H "Authorization: Bearer $TOKEN")
echo $list_response | jq

echo -e "\n✅ All async API tests completed!"
echo -e "\n📋 Summary:"
echo "   🔓 Public endpoints (no auth): health, search, job status, cache refresh"
echo "   🔒 Protected endpoints (auth required): add pod, upload, put subject data, add pod ref, list pods"
echo "   🔑 Authentication: JWT token with keystore password verification"
