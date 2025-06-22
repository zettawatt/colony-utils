# Async Job System

The colony-daemon now supports asynchronous job-based operations to handle long-running tasks without client timeouts.

## Overview

Long-running operations like cache refresh, upload all, search, etc. can now be executed asynchronously. Clients start a job and receive a job ID immediately, then poll for status and results.

## Key Features

- **Mutual Exclusion**: Only one long-running operation can run at a time
- **Job Tracking**: Each job has a unique ID, status, progress, and result
- **Progress Updates**: Jobs report progress from 0.0 to 1.0
- **Error Handling**: Failed jobs include error details

## Job Lifecycle

1. **Pending**: Job created but not yet started
2. **Running**: Job is actively executing
3. **Completed**: Job finished successfully
4. **Failed**: Job encountered an error

## API Endpoints

### Start Job Operations

- `POST /api/v1/jobs/cache/refresh` - Start cache refresh job
- `POST /api/v1/jobs/cache/upload` - Start upload all job
- `POST /api/v1/jobs/cache/refresh/{depth}` - Start refresh ref job with depth
- `POST /api/v1/jobs/search?q=query&limit=10` - Start search job
- `POST /api/v1/jobs/search/subject/{subject}` - Start get subject data job

### Job Management

- `GET /api/v1/jobs/{job_id}` - Get job status and progress
- `GET /api/v1/jobs/{job_id}/result` - Get job result (only when completed)

## Usage Examples

### Starting a Job

```bash
# Start a cache refresh job
curl -X POST "http://localhost:3000/api/v1/jobs/cache/refresh" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Response:
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "message": "Cache refresh job started",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Checking Job Status

```bash
# Check job status
curl "http://localhost:3000/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Response:
{
  "job": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "job_type": "refreshcache",
    "status": "running",
    "progress": 0.5,
    "message": "Starting cache refresh",
    "result": null,
    "error": null,
    "created_at": "2024-01-01T12:00:00Z",
    "updated_at": "2024-01-01T12:00:30Z"
  }
}
```

### Getting Job Result

```bash
# Get job result (when completed)
curl "http://localhost:3000/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000/result" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Response:
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "result": {
    "status": "success",
    "message": "Cache refreshed successfully",
    "timestamp": "2024-01-01T12:01:00Z"
  },
  "error": null
}
```

## Error Handling

### Job Creation Conflicts

If you try to start a job while another is running:

```json
{
  "error": "JOB_CREATION_FAILED",
  "message": "Another operation is already running",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Job Not Found

```json
{
  "error": "JOB_NOT_FOUND",
  "message": "Job with ID abc123 not found",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Job Not Completed

When requesting results for a job that's still running:

```json
{
  "error": "JOB_NOT_COMPLETED",
  "message": "Job abc123 is not yet completed",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Legacy Endpoints

The original synchronous endpoints are still available for backward compatibility:

- `POST /api/v1/cache` - Synchronous cache refresh
- `PUT /api/v1/cache` - Synchronous upload all
- `POST /api/v1/cache/{depth}` - Synchronous refresh ref
- `GET /api/v1/search` - Synchronous search
- `GET /api/v1/search/subject/{subject}` - Synchronous get subject data

## Implementation Notes

- Jobs are stored in memory and will be lost on server restart
- Only one operation can run at a time to prevent resource conflicts
- Progress updates are approximate and may not be linear
- Job IDs are UUIDs generated using the uuid crate
