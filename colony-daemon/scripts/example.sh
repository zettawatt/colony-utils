#!/bin/bash

# Colony Daemon Async API Test Script
BASE_URL="http://localhost:3000"

echo "🚀 Testing Colony Daemon Async REST API"
echo "========================================"

# Function to poll job status until completion
poll_job() {
    local job_id=$1
    local operation_name=$2
    echo "⏳ Polling job $job_id for $operation_name..."

    while true; do
        response=$(curl -s -X GET "$BASE_URL/api/v1/jobs/$job_id" \
            -H "Authorization: Bearer $TOKEN")

        status=$(echo $response | jq -r '.job.status')
        progress=$(echo $response | jq -r '.job.progress // 0')
        message=$(echo $response | jq -r '.job.message // ""')

        echo "   Status: $status, Progress: $(printf "%.1f" $progress), Message: $message"

        if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
            break
        fi

        sleep 20
    done

    if [ "$status" = "completed" ]; then
        echo "✅ $operation_name completed successfully!"
        # Get the result
        echo "📋 Getting result for $operation_name..."
        curl -s -X GET "$BASE_URL/api/v1/jobs/$job_id/result" \
            -H "Authorization: Bearer $TOKEN" | jq
    else
        echo "❌ $operation_name failed!"
        echo $response | jq
    fi
}

# Get JWT token
echo "📝 Getting JWT token..."
TOKEN=$(curl -s -X POST $BASE_URL/auth/token -H "Content-Type: application/json" | jq -r '.token')
if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "❌ Failed to get JWT token"
    exit 1
fi
echo "✅ Token obtained: ${TOKEN:0:20}..."

# Health check
echo -e "\n🏥 Testing health check..."
curl -s -X GET $BASE_URL/health | jq

 # Test async cache refresh
 echo -e "\n🔄 Testing async cache refresh..."
 cache_response=$(curl -s -X POST $BASE_URL/api/v1/jobs/cache/refresh \
   -H "Authorization: Bearer $TOKEN")
 echo $cache_response | jq
 cache_job_id=$(echo $cache_response | jq -r '.job_id')

 if [ "$cache_job_id" != "null" ] && [ ! -z "$cache_job_id" ]; then
     poll_job $cache_job_id "Cache Refresh"
 fi

 # Test async refresh pod references with depth
echo -e "\n📋 Testing async refresh pod references (depth 2)..."
refresh_response=$(curl -s -X POST $BASE_URL/api/v1/jobs/cache/refresh/2 \
 -H "Authorization: Bearer $TOKEN")
echo $refresh_response | jq
refresh_job_id=$(echo $refresh_response | jq -r '.job_id')

if [ "$refresh_job_id" != "null" ] && [ ! -z "$refresh_job_id" ]; then
   poll_job $refresh_job_id "Refresh Pod References"
fi

# Add a pod
 echo -e "\n➕ Testing add pod..."
 POD_RESPONSE=$(curl -s -X POST $BASE_URL/api/v1/pods \
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
    echo -e "\n💾 Testing put subject data (synchronous)..."
    curl -s -X PUT $BASE_URL/api/v1/pods/$POD_ADDRESS/c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59 \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "@context": {"schema": "http://schema.org/"},
        "@type": "schema:MediaObject",
        "@id": "ant://c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59",
        "schema:name": "BegBlag.mp3",
        "schema:description": "Beg Blag and Steal",
        "schema:contentSize": "4MB"        
      }'

    echo -e "\n📖 Testing async get subject data..."
    subject_response=$(curl -s -X POST $BASE_URL/api/v1/jobs/search/subject/$SUBJECT_ADDRESS \
      -H "Authorization: Bearer $TOKEN")
    echo $subject_response | jq
    subject_job_id=$(echo $subject_response | jq -r '.job_id')

    if [ "$subject_job_id" != "null" ] && [ ! -z "$subject_job_id" ]; then
        poll_job $subject_job_id "Get Subject Data"
    fi

    echo -e "\n🔗 Testing add pod reference (synchronous)..."
    POD_REF_ADDRESS=8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e
    curl -s -X POST $BASE_URL/api/v1/pods/$POD_ADDRESS/pod_ref \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "pod_ref": "ant://8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e"
      }'

    # echo -e "\n🗑️ Testing remove pod reference (synchronous)..."
    # curl -s -X DELETE "$BASE_URL/api/v1/pods/$POD_ADDRESS/pod_ref?pod_ref=test-reference-address" \
    #   -H "Authorization: Bearer $TOKEN"
fi

# Test async search
echo -e "\n🔍 Testing async search..."
search_response=$(curl -s -X POST "$BASE_URL/api/v1/jobs/search" \
  -H "Authorization: Bearer $TOKEN" \
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

# Test async upload all pods
echo -e "\n⬆️ Testing async upload all pods..."
upload_response=$(curl -s -X POST $BASE_URL/api/v1/jobs/cache/upload \
  -H "Authorization: Bearer $TOKEN")
echo $upload_response | jq
upload_job_id=$(echo $upload_response | jq -r '.job_id')

if [ "$upload_job_id" != "null" ] && [ ! -z "$upload_job_id" ]; then
    poll_job $upload_job_id "Upload All Pods"
fi

# Demonstrate checking job status for a non-existent job
echo -e "\n🔍 Testing job status for non-existent job..."
curl -s -X GET "$BASE_URL/api/v1/jobs/non-existent-job-id" \
  -H "Authorization: Bearer $TOKEN" | jq

echo -e "\n✅ All async API tests completed!"
