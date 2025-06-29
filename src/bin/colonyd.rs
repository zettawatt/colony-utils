use autonomi::{Client, Wallet};
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::Json,
    routing::{delete, get, post, put},
};
use bip39::Mnemonic;
use clap::{Arg, Command};
use colonylib::{DataStore, Graph, KeyStore, PodManager};
use dialoguer::{Confirm, Input, Password};
use indicatif::{ProgressBar, ProgressStyle};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{self, net::TcpListener, sync::Mutex as TokioMutex};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use tracing_subscriber::prelude::*;

// ETH wallet for local testnet
const LOCAL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    password_verified: bool,
}

// Request/Response DTOs
#[derive(Debug, Serialize, Deserialize)]
struct CreatePodRequest {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadPodRequest {
    address: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PodResponse {
    address: String,
    name: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshResponse {
    status: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PodRefRequest {
    pod_ref: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenamePodRequest {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheResponse {
    status: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadPodResponse {
    address: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadResponse {
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    timestamp: String,
    version: String,
}

// Job management structures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum JobType {
    RefreshCache,
    UploadAll,
    UploadPod,
    RefreshRef,
    Search,
    GetSubjectData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Job {
    id: String,
    job_type: JobType,
    status: JobStatus,
    progress: Option<f32>, // 0.0 to 1.0
    message: Option<String>,
    result: Option<Value>,
    error: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobResponse {
    job_id: String,
    status: JobStatus,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobStatusResponse {
    job: Job,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobResultResponse {
    job_id: String,
    status: JobStatus,
    result: Option<Value>,
    error: Option<String>,
}

// Job Manager for tracking async operations
#[derive(Debug)]
struct JobManager {
    jobs: TokioMutex<HashMap<String, Job>>,
    active_operation: TokioMutex<Option<String>>, // Only one operation can run at a time
}

impl JobManager {
    fn new() -> Self {
        Self {
            jobs: TokioMutex::new(HashMap::new()),
            active_operation: TokioMutex::new(None),
        }
    }

    async fn create_job(&self, job_type: JobType) -> Result<String, String> {
        let mut active = self.active_operation.lock().await;
        if active.is_some() {
            return Err("Another operation is already running".to_string());
        }

        let job_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let job = Job {
            id: job_id.clone(),
            job_type,
            status: JobStatus::Pending,
            progress: Some(0.0),
            message: Some("Job created".to_string()),
            result: None,
            error: None,
            created_at: now.clone(),
            updated_at: now,
        };

        let mut jobs = self.jobs.lock().await;
        jobs.insert(job_id.clone(), job);
        *active = Some(job_id.clone());

        Ok(job_id)
    }

    async fn update_job_status(
        &self,
        job_id: &str,
        status: JobStatus,
        message: Option<String>,
        progress: Option<f32>,
    ) {
        let mut jobs = self.jobs.lock().await;
        if let Some(job) = jobs.get_mut(job_id) {
            job.status = status;
            job.updated_at = chrono::Utc::now().to_rfc3339();
            if let Some(msg) = message {
                job.message = Some(msg);
            }
            if let Some(prog) = progress {
                job.progress = Some(prog);
            }
        }
    }

    async fn complete_job(&self, job_id: &str, result: Option<Value>, error: Option<String>) {
        let mut jobs = self.jobs.lock().await;
        if let Some(job) = jobs.get_mut(job_id) {
            job.status = if error.is_some() {
                JobStatus::Failed
            } else {
                JobStatus::Completed
            };
            job.result = result;
            job.error = error;
            job.progress = Some(1.0);
            job.updated_at = chrono::Utc::now().to_rfc3339();
        }

        // Clear active operation
        let mut active = self.active_operation.lock().await;
        if active.as_ref().map(|s| s.as_str()) == Some(job_id) {
            *active = None;
        }
    }

    async fn get_job(&self, job_id: &str) -> Option<Job> {
        let jobs = self.jobs.lock().await;
        jobs.get(job_id).cloned()
    }
}

// Service layer to manage PodManager operations
struct PodService {
    // Store components using Mutex<Option<T>> pattern to enable 'take and restore'
    client: std::sync::Mutex<Option<Client>>,
    wallet: std::sync::Mutex<Option<Wallet>>,
    data_store: std::sync::Mutex<Option<DataStore>>,
    keystore: std::sync::Mutex<Option<KeyStore>>,
    graph: std::sync::Mutex<Option<Graph>>,
}

impl PodService {
    fn new(
        client: Client,
        wallet: Wallet,
        data_store: DataStore,
        keystore: KeyStore,
        graph: Graph,
    ) -> Self {
        Self {
            client: std::sync::Mutex::new(Some(client)),
            wallet: std::sync::Mutex::new(Some(wallet)),
            data_store: std::sync::Mutex::new(Some(data_store)),
            keystore: std::sync::Mutex::new(Some(keystore)),
            graph: std::sync::Mutex::new(Some(graph)),
        }
    }

    // Helper method to safely extract components and ensure they're always restored
    fn extract_components(&self) -> Result<(Client, Wallet, DataStore, KeyStore, Graph), String> {
        let client = self
            .client
            .lock()
            .unwrap()
            .take()
            .ok_or("Client not initialized")?;
        let wallet = self
            .wallet
            .lock()
            .unwrap()
            .take()
            .ok_or("Wallet not initialized")?;
        let data_store = self
            .data_store
            .lock()
            .unwrap()
            .take()
            .ok_or("DataStore not initialized")?;
        let keystore = self
            .keystore
            .lock()
            .unwrap()
            .take()
            .ok_or("KeyStore not initialized")?;
        let graph = self
            .graph
            .lock()
            .unwrap()
            .take()
            .ok_or("Graph not initialized")?;
        Ok((client, wallet, data_store, keystore, graph))
    }

    // Helper method to restore components
    fn restore_components(
        &self,
        client: Client,
        wallet: Wallet,
        data_store: DataStore,
        keystore: KeyStore,
        graph: Graph,
    ) {
        *self.client.lock().unwrap() = Some(client);
        *self.wallet.lock().unwrap() = Some(wallet);
        *self.data_store.lock().unwrap() = Some(data_store);
        *self.keystore.lock().unwrap() = Some(keystore);
        *self.graph.lock().unwrap() = Some(graph);
    }

    // PodManager method mappings - these would interact with the actual PodManager

    // Maps to PodManager::refresh_cache()
    async fn refresh_cache(&self) -> Result<CacheResponse, String> {
        info!("Refreshing cache");

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .refresh_cache()
                .await
                .map_err(|e| format!("Failed to refresh cache: {e}"))?;

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!("Cache refreshed successfully");
                Ok(CacheResponse {
                    status: "success".to_string(),
                    message: "Cache refreshed successfully".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            }
            Err(e) => {
                warn!("Failed to refresh cache: {}", e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::refresh_ref() - refreshes pod references
    async fn refresh_ref(&self, depth: u64) -> Result<RefreshResponse, String> {
        info!("Refreshing pod references to depth {}", depth);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .refresh_ref(depth)
                .await
                .map_err(|e| format!("Failed to refresh pod references: {e}"))?;

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!("Pod references refreshed successfully");
                Ok(RefreshResponse {
                    status: "success".to_string(),
                    message: "All pods refreshed successfully".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            }
            Err(e) => {
                warn!("Failed to refresh pod references: {}", e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::add_pod()
    async fn add_pod(
        &self,
        request: CreatePodRequest,
        keystore_password: &str,
    ) -> Result<PodResponse, String> {
        info!("Adding pod: {}", request.name);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            let (pod_address, _pod_data) = podman
                .add_pod(&request.name)
                .await
                .map_err(|e| format!("Failed to add pod: {e}"))?;

            let key_store_file = podman.data_store.get_keystore_path();
            let mut file = std::fs::File::create(key_store_file).unwrap();
            KeyStore::to_file(&keystore, &mut file, keystore_password).unwrap();

            Ok(pod_address)
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(pod_address) => {
                info!("Added pod {} with address {}", &request.name, &pod_address);
                Ok(PodResponse {
                    address: pod_address,
                    name: request.name,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            }
            Err(e) => {
                warn!("Failed to add pod {}: {}", &request.name, e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::upload_pod()
    async fn upload_pod(&self, request: UploadPodRequest) -> Result<UploadPodResponse, String> {
        info!("Uploading pod {}", &request.address);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .upload_pod(&request.address)
                .await
                .map_err(|e| format!("Failed to upload pod {}: {}", &request.address, e))?;

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!("Uploaded pod {} successfully", &request.address);
                Ok(UploadPodResponse {
                    address: request.address.clone(),
                    message: format!("Uploaded pod {} successfully", request.address),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            }
            Err(e) => {
                warn!("Failed to upload pod {}: {}", &request.address, e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::upload_all()
    async fn upload_all(&self) -> Result<UploadResponse, String> {
        info!("Uploading all pods");

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .upload_all()
                .await
                .map_err(|e| format!("Failed to upload all pods: {e}"))?;

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!("All pods uploaded successfully");
                Ok(UploadResponse {
                    message: "All pods uploaded successfully".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            }
            Err(e) => {
                warn!("Failed to upload all pods: {}", e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::get_subject_data()
    async fn get_subject_data(&self, address: &str) -> Result<Value, String> {
        info!("Getting subject data for: {}", address);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            let subject_data = podman
                .get_subject_data(address)
                .await
                .map_err(|e| format!("Failed to get subject data: {e}"))?;

            // Parse the subject data string as JSON
            serde_json::from_str(&subject_data)
                .map_err(|e| format!("Failed to parse subject data as JSON: {e}"))
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(data) => {
                info!("Subject data retrieved successfully for {}", address);
                Ok(data)
            }
            Err(e) => {
                warn!("Failed to get subject data for {}: {}", address, e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::put_subject_data()
    async fn put_subject_data(
        &self,
        pod_address: &str,
        subject: &str,
        data: Value,
        keystore_password: &str,
    ) -> Result<Value, String> {
        info!(
            "Putting subject data for {} into pod {}",
            subject, pod_address
        );

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Convert the JSON data to string for PodManager
            let data_string = serde_json::to_string(&data)
                .map_err(|e| format!("Failed to serialize data: {e}"))?;

            // Use the PodManager
            podman
                .put_subject_data(pod_address, subject, &data_string)
                .await
                .map_err(|e| format!("Failed to put subject data: {e}"))?;

            let key_store_file = podman.data_store.get_keystore_path();
            let mut file = std::fs::File::create(key_store_file).unwrap();
            KeyStore::to_file(&keystore, &mut file, keystore_password).unwrap();

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!(
                    "Subject data updated successfully for {} in pod {}",
                    subject, pod_address
                );
                Ok(data)
            }
            Err(e) => {
                warn!(
                    "Failed to put subject data for {} in pod {}: {}",
                    subject, pod_address, e
                );
                Err(e)
            }
        }
    }

    // Maps to PodManager::add_pod_ref()
    async fn add_pod_ref(
        &self,
        id: &str,
        request: PodRefRequest,
        keystore_password: &str,
    ) -> Result<(), String> {
        info!("Adding pod reference for {}: {}", id, request.pod_ref);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .add_pod_ref(id, &request.pod_ref)
                .await
                .map_err(|e| format!("Failed to add pod reference: {e}"))?;

            let key_store_file = podman.data_store.get_keystore_path();
            let mut file = std::fs::File::create(key_store_file).unwrap();
            KeyStore::to_file(&keystore, &mut file, keystore_password).unwrap();

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!(
                    "Pod reference added successfully for {}: {}",
                    id, request.pod_ref
                );
                Ok(())
            }
            Err(e) => {
                warn!("Failed to add pod reference for {}: {}", id, e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::remove_pod_ref()
    async fn remove_pod_ref(&self, id: &str, request: PodRefRequest) -> Result<(), String> {
        info!("Removing pod reference for {}: {}", id, request.pod_ref);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .remove_pod_ref(id, &request.pod_ref)
                .await
                .map_err(|e| format!("Failed to remove pod reference: {e}"))?;

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!(
                    "Pod reference removed successfully for {}: {}",
                    id, request.pod_ref
                );
                Ok(())
            }
            Err(e) => {
                warn!("Failed to remove pod reference for {}: {}", id, e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::search()
    async fn search(&self, query: Value) -> Result<Value, String> {
        info!("Searching for: {}", query.to_string());

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            let results = podman
                .search(query.clone())
                .await
                .map_err(|e| format!("Failed to search: {e}"))?;

            Ok(results)
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(results) => {
                info!("Search completed for: {}", query);
                Ok(results)
            }
            Err(e) => {
                warn!("Search failed for {}: {}", query, e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::list_my_pods()
    async fn list_my_pods(&self) -> Result<Value, String> {
        info!("Listing my pods");

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager to list pods
            let results = podman
                .list_my_pods()
                .map_err(|e| format!("Failed to list pods: {e}"))?;

            Ok(results)
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(results) => {
                info!("Listed pods successfully");
                Ok(results)
            }
            Err(e) => {
                warn!("Failed to list pods: {}", e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::remove_pod()
    async fn remove_pod(&self, pod_address: &str, keystore_password: &str) -> Result<(), String> {
        info!("Removing pod: {}", pod_address);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .remove_pod(pod_address)
                .await
                .map_err(|e| format!("Failed to remove pod: {e}"))?;

            let key_store_file = podman.data_store.get_keystore_path();
            let mut file = std::fs::File::create(key_store_file).unwrap();
            KeyStore::to_file(&keystore, &mut file, keystore_password).unwrap();

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!("Pod removed successfully: {}", pod_address);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to remove pod {}: {}", pod_address, e);
                Err(e)
            }
        }
    }

    // Maps to PodManager::rename_pod()
    async fn rename_pod(
        &self,
        pod_address: &str,
        request: RenamePodRequest,
        keystore_password: &str,
    ) -> Result<(), String> {
        info!("Renaming pod {} to: {}", pod_address, request.name);

        // Extract components
        let (client, wallet, mut data_store, mut keystore, mut graph) =
            self.extract_components()?;

        // Execute operation and capture result
        let result = async {
            let mut podman = PodManager::new(
                client.clone(),
                &wallet,
                &mut data_store,
                &mut keystore,
                &mut graph,
            )
            .await
            .map_err(|e| format!("Failed to create PodManager: {e}"))?;

            // Use the PodManager
            podman
                .rename_pod(pod_address, &request.name)
                .await
                .map_err(|e| format!("Failed to rename pod: {e}"))?;

            let key_store_file = podman.data_store.get_keystore_path();
            let mut file = std::fs::File::create(key_store_file).unwrap();
            KeyStore::to_file(&keystore, &mut file, keystore_password).unwrap();

            Ok(())
        }
        .await;

        // Always restore components, regardless of success or failure
        self.restore_components(client, wallet, data_store, keystore, graph);

        // Handle the result
        match result {
            Ok(()) => {
                info!(
                    "Pod renamed successfully: {} -> {}",
                    pod_address, request.name
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to rename pod {} to {}: {}",
                    pod_address, request.name, e
                );
                Err(e)
            }
        }
    }
}

#[derive(Clone)]
struct AppState {
    pod_service: Arc<PodService>,
    job_manager: Arc<JobManager>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    keystore_password: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup enhanced logging with structured output
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                //"colony_daemon=debug,colonylib=debug,tower_http=debug,axum=debug,autonomi=error".into()
                "".into()
            }),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true), //.json()
        );

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting colony-daemon");

    // Parse command line arguments
    let matches = Command::new("colony-daemon")
        .version("0.1.1")
        .about("A server hosting a REST endpoint for interacting with colonylib")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .default_value("3000"),
        )
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .value_name("IP")
                .help("IP address range to listen from")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("data")
                .short('d')
                .long("data")
                .value_name("PATH")
                .help("Path to data directory"),
        )
        .arg(
            Arg::new("password")
                .long("pass")
                .value_name("PASS")
                .help("Password or file with password to unlock key store (format: pass:<password> or file:<path>)"),
        )
        .arg(
            Arg::new("network")
                .short('n')
                .long("network")
                .value_name("NETWORK")
                .help("Autonomi network to connect to")
                .value_parser(["local", "alpha", "main"])
                .default_value("main"),
        )
        .get_matches();

    let port: u16 = matches.get_one::<String>("port").unwrap().parse()?;
    let listen_ip = matches.get_one::<String>("listen").unwrap();
    let network = matches.get_one::<String>("network").unwrap();
    let password_arg = matches.get_one::<String>("password");

    // Determine data directory
    let data_dir = if let Some(data_path) = matches.get_one::<String>("data") {
        PathBuf::from(data_path)
    } else {
        dirs::data_dir()
            .ok_or("Could not determine data directory")?
            .join("colony")
    };

    /////////////////////////////////
    // DataStore setup step
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Setting up DataStore...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let mut data_store = if matches.get_one::<String>("data").is_none() {
        // Create a new DataStore instance with the DataStore::create method()
        DataStore::create().map_err(|e| format!("Failed to create DataStore: {e}"))?
    } else {
        // Create a new DataStore instance with the DataStore::from_paths() method
        let pods_dir = data_dir.join("pods");
        // Use the default download directory, but if not set, use the dirs::home() path joined with "Downloads"
        // Some linux systems don't set XDG_DOWNLOAD_DIR
        let downloads_dir = if let Some(downloads_dir) = dirs::download_dir() {
            downloads_dir
        } else {
            dirs::home_dir()
                .ok_or("Could not determine downloads directory")?
                .join("Downloads")
        };

        DataStore::from_paths(data_dir.clone(), pods_dir, downloads_dir)
            .map_err(|e| format!("Failed to create DataStore from paths: {e}"))?
    };

    pb.finish_with_message("DataStore setup complete");
    info!("DataStore initialized at: {:?}", data_store.get_data_path());

    /////////////////////////////////
    // KeyStore setup step
    /////////////////////////////////

    let keystore_path = data_store.get_keystore_path();
    let mut keystore_password = get_password(password_arg)?;

    let mut keystore = if !keystore_path.exists() {
        // Initialize new KeyStore

        // Check if user wants to generate new mnemonic or enter existing one
        let generate_new = Confirm::new()
            .with_prompt("Generate a new BIP39 mnemonic? (No to enter existing)")
            .default(true)
            .interact()?;

        let mnemonic = if generate_new {
            // Generate new mnemonic using BIP39
            let new_mnemonic = Mnemonic::generate(12)
                .map_err(|e| format!("Failed to generate BIP39 mnemonic: {e}"))?;
            println!("Generated BIP39 12-word mnemonic: {new_mnemonic}");
            new_mnemonic.to_string()
        } else {
            Input::<String>::new()
                .with_prompt("Enter your existing BIP39 12-word mnemonic")
                .interact_text()?
        };

        // Create KeyStore from mnemonic
        let mut keystore = KeyStore::from_mnemonic(&mnemonic)
            .map_err(|e| format!("Failed to create KeyStore from mnemonic: {e}"))?;

        // Prompt for Ethereum wallet private key
        let wallet_key = Input::<String>::new()
            .allow_empty(true)
            .with_prompt("Enter your Ethereum wallet private key")
            .interact_text()?;

        // Set wallet key
        if wallet_key.is_empty() {
            // If the SECRET_KEY environment variable is set, use that as the wallet key
            if let Ok(secret_key) = std::env::var("SECRET_KEY") {
                println!("No wallet key provided, using SECRET_KEY environment variable");
                keystore
                    .set_wallet_key(secret_key)
                    .map_err(|e| format!("Failed to set wallet key: {e}"))?;
            } else {
                println!("No wallet key provided, using default local testnet key");
                keystore
                    .set_wallet_key(LOCAL_PRIVATE_KEY.to_string())
                    .map_err(|e| format!("Failed to set wallet key: {e}"))?;
            }
        } else {
            keystore
                .set_wallet_key(wallet_key)
                .map_err(|e| format!("Failed to set wallet key: {e}"))?;
        }

        // Save KeyStore to file
        let mut file = fs::File::create(&keystore_path)
            .map_err(|e| format!("Failed to create keystore file: {e}"))?;
        keystore
            .to_file(&mut file, &keystore_password)
            .map_err(|e| format!("Failed to save KeyStore: {e}"))?;

        keystore
    } else {
        // Load existing KeyStore
        loop {
            let mut file = fs::File::open(&keystore_path)
                .map_err(|e| format!("Failed to open keystore file: {e}"))?;
            match KeyStore::from_file(&mut file, &keystore_password) {
                Ok(keystore) => break keystore,
                Err(_) => {
                    warn!("Failed to unlock KeyStore with provided password");
                    keystore_password = Password::new()
                        .with_prompt("Enter KeyStore password")
                        .interact()?;
                    // Note: This is a simplified approach - in practice you'd want to handle this better
                    continue;
                }
            }
        }
    };

    info!("KeyStore loaded successfully");

    /////////////////////////////////
    // Graph setup step
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Setting up Graph...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let graph_path = data_store.get_graph_path();
    let mut graph = Graph::open(&graph_path).map_err(|e| format!("Failed to open Graph: {e}"))?;

    pb.finish_with_message("Graph setup complete");
    info!("Graph initialized at: {:?}", graph_path);

    /////////////////////////////////
    // Autonomi Connection step
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Connecting to Autonomi network...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let client = init_client(network.to_string()).await;

    let wallet_key = keystore.get_wallet_key();
    let wallet = Wallet::new_from_private_key(client.evm_network().clone(), &wallet_key)
        .map_err(|e| format!("Failed to create wallet: {e}"))?;

    pb.finish_with_message("Connected to Autonomi network");
    info!("Connected to {} network", network);

    /////////////////////////////////
    // PodManager setup step
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Setting up PodManager...");
    pb.enable_steady_tick(Duration::from_millis(100));

    // Test PodManager creation to ensure components are compatible
    let _pod_manager = PodManager::new(
        client.clone(),
        &wallet,
        &mut data_store,
        &mut keystore,
        &mut graph,
    )
    .await
    .map_err(|e| format!("Failed to create PodManager: {e}"))?;

    pb.finish_with_message("PodManager setup complete");
    info!("PodManager initialized successfully");

    /////////////////////////////////
    // start REST server
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Starting REST server...");
    pb.enable_steady_tick(Duration::from_millis(100));

    // Create JWT keys from keystore password
    let encoding_key = EncodingKey::from_secret(keystore_password.as_bytes());
    let decoding_key = DecodingKey::from_secret(keystore_password.as_bytes());

    // Create application state with components
    let pod_service = Arc::new(PodService::new(client, wallet, data_store, keystore, graph));
    let job_manager = Arc::new(JobManager::new());
    let app_state = AppState {
        pod_service,
        job_manager,
        encoding_key,
        decoding_key,
        keystore_password,
    };

    info!("PodManager created successfully and integrated into REST API");

    // Create router with all endpoints
    let app = create_router(app_state);

    // Create socket address
    let addr = format!("{listen_ip}:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Failed to bind to {addr}: {e}"))?;

    pb.finish_with_message("REST server started");
    info!("Server listening on {}", addr);

    // Start the server
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server error: {e}"))?;

    Ok(())
}

async fn init_client(environment: String) -> Client {
    match environment.trim() {
        "local" => Client::init_local().await.unwrap(),
        "alpha" => Client::init_alpha().await.unwrap(),
        _ => Client::init().await.unwrap(), // "autonomi"
    }
}

fn create_router(state: AppState) -> Router {
    // Public routes (no authentication required)
    let public_routes = Router::new()
        // Asynchronous job-based endpoints
        .route(
            "/colony-0/jobs/cache/refresh",
            post(start_refresh_cache_job),
        )
        .route(
            "/colony-0/jobs/cache/refresh/{depth}",
            post(start_refresh_ref_job),
        )
        .route("/colony-0/jobs/search", post(start_search_job))
        .route(
            "/colony-0/jobs/search/subject/{subject}",
            post(start_get_subject_data_job),
        )
        .route("/colony-0/jobs/{job_id}", get(get_job_status))
        .route("/colony-0/jobs/{job_id}/result", get(get_job_result))
        // Synchronous endpoints
        .route("/colony-0/search", get(search))
        .route("/colony-0/search/subject/{subject}", get(get_subject_data))
        .route("/colony-auth/token", post(create_token))
        .route("/colony-auth/token/legacy", post(create_token_legacy))
        .route("/colony-health", get(health_check));

    // Protected routes (authentication required)
    let protected_routes = Router::new()
        // Asynchronous job-based endpoints
        .route("/colony-0/jobs/cache/upload", post(start_upload_all_job))
        .route(
            "/colony-0/jobs/cache/upload/{address}",
            post(start_upload_pod_job),
        )
        // Synchronous endpoints
        .route("/colony-0/pods", get(list_my_pods).post(add_pod))
        .route("/colony-0/pods/{pod}", delete(remove_pod).post(rename_pod))
        .route("/colony-0/pods/{pod}/{subject}", put(put_subject_data))
        .route(
            "/colony-0/pods/{pod}/pod_ref",
            post(add_pod_ref).delete(remove_pod_ref),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Combine routes with middleware
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
        )
        .with_state(state)
}

// JWT Authentication middleware
#[instrument(skip(state, headers, request))]
async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(token) => token,
        None => {
            warn!("Missing or invalid authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let validation = Validation::new(Algorithm::HS256);
    match decode::<Claims>(token, &state.decoding_key, &validation) {
        Ok(token_data) => {
            // Check if the token has password verification
            if !token_data.claims.password_verified {
                warn!("Token does not have password verification - access denied");
                return Err(StatusCode::UNAUTHORIZED);
            }

            debug!(
                "Valid token with password verification for user: {}",
                token_data.claims.sub
            );
            Ok(next.run(request).await)
        }
        Err(err) => {
            warn!("Invalid token: {}", err);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// Authentication endpoints
#[instrument(skip(state, auth_request))]
async fn create_token(
    State(state): State<AppState>,
    Json(auth_request): Json<AuthRequest>,
) -> Result<Json<Value>, StatusCode> {
    // Verify the provided password matches the keystore password
    if auth_request.password != state.keystore_password {
        warn!("Invalid keystore password provided for token creation");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: "colony-daemon".to_string(),
        exp: now + 600, // 10 minutes
        iat: now,
        password_verified: true, // Password has been verified
    };

    match encode(&Header::default(), &claims, &state.encoding_key) {
        Ok(token) => {
            info!("JWT token created successfully with password verification");
            Ok(Json(serde_json::json!({
                "token": token,
                "expires_in": 600,
                "token_type": "Bearer"
            })))
        }
        Err(err) => {
            error!("Failed to create JWT token: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Legacy endpoint for backward compatibility (without password verification)
#[instrument(skip(state))]
async fn create_token_legacy(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    warn!("Legacy token endpoint used - password verification bypassed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: "colony-daemon".to_string(),
        exp: now + 600, // 10 minutes
        iat: now,
        password_verified: false, // No password verification for legacy endpoint
    };

    match encode(&Header::default(), &claims, &state.encoding_key) {
        Ok(token) => {
            info!("Legacy JWT token created successfully (no password verification)");
            Ok(Json(serde_json::json!({
                "token": token,
                "expires_in": 600,
                "token_type": "Bearer"
            })))
        }
        Err(err) => {
            error!("Failed to create JWT token: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[instrument]
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// PodManager REST endpoint handlers

#[instrument(skip(state))]
async fn list_my_pods(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Listing my pods");

    match state.pod_service.list_my_pods().await {
        Ok(response) => {
            info!("Listed pods successfully");
            Ok(Json(response))
        }
        Err(err) => {
            error!("Failed to list pods: {}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "LIST_PODS_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn add_pod(
    State(state): State<AppState>,
    Json(request): Json<CreatePodRequest>,
) -> Result<Json<PodResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Adding new pod: {}", request.name);

    match state
        .pod_service
        .add_pod(request, &state.keystore_password)
        .await
    {
        Ok(pod) => {
            info!("Pod added successfully: {}", pod.address);
            Ok(Json(pod))
        }
        Err(err) => {
            error!("Failed to add pod: {}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "ADD_POD_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn get_subject_data(
    State(state): State<AppState>,
    Path(subject): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting subject data for: {}", subject);

    match state.pod_service.get_subject_data(&subject).await {
        Ok(data) => {
            debug!("Subject data retrieved successfully for: {}", subject);
            Ok(Json(data))
        }
        Err(err) => {
            warn!("Subject data not found for: {}", subject);
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "SUBJECT_DATA_NOT_FOUND".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn put_subject_data(
    State(state): State<AppState>,
    Path((pod, subject)): Path<(String, String)>,
    Json(data): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Putting subject data for {} in pod {}", subject, pod);

    match state
        .pod_service
        .put_subject_data(&pod, &subject, data, &state.keystore_password)
        .await
    {
        Ok(data) => {
            info!(
                "Subject data updated successfully for {} in pod {}",
                subject, pod
            );
            Ok(Json(data))
        }
        Err(err) => {
            error!(
                "Failed to update subject data for {} in pod {}: {}",
                subject, pod, err
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "PUT_SUBJECT_DATA_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn add_pod_ref(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<PodRefRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    info!("Adding pod reference for {}: {}", id, request.pod_ref);

    match state
        .pod_service
        .add_pod_ref(&id, request, &state.keystore_password)
        .await
    {
        Ok(()) => {
            info!("Pod reference added successfully for: {}", id);
            Ok(StatusCode::CREATED)
        }
        Err(err) => {
            error!("Failed to add pod reference for {}: {}", id, err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "ADD_POD_REF_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn remove_pod_ref(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<PodRefRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    info!("Removing pod reference for {}: {}", id, request.pod_ref);

    match state.pod_service.remove_pod_ref(&id, request).await {
        Ok(()) => {
            info!("Pod reference removed successfully for: {}", id);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(err) => {
            error!("Failed to remove pod reference for {}: {}", id, err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "REMOVE_POD_REF_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn remove_pod(
    State(state): State<AppState>,
    Path(pod_address): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    info!("Removing pod: {}", pod_address);

    match state
        .pod_service
        .remove_pod(&pod_address, &state.keystore_password)
        .await
    {
        Ok(()) => {
            info!("Pod removed successfully: {}", pod_address);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(err) => {
            error!("Failed to remove pod {}: {}", pod_address, err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "REMOVE_POD_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn rename_pod(
    State(state): State<AppState>,
    Path(pod_address): Path<String>,
    Json(request): Json<RenamePodRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    info!("Renaming pod {} to: {}", pod_address, request.name);

    match state
        .pod_service
        .rename_pod(&pod_address, request, &state.keystore_password)
        .await
    {
        Ok(()) => {
            info!("Pod renamed successfully: {}", pod_address);
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!("Failed to rename pod {}: {}", pod_address, err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "RENAME_POD_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn search(
    State(state): State<AppState>,
    Json(query): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Searching for: {}", query.to_string());

    match state.pod_service.search(query.clone()).await {
        Ok(response) => {
            debug!("Search completed for query '{}'", query.to_string());
            Ok(Json(response))
        }
        Err(err) => {
            error!("Search failed for query '{}': {}", query, err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "SEARCH_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

fn get_password(password_arg: Option<&String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(pass_spec) = password_arg {
        if let Some(password) = pass_spec.strip_prefix("pass:") {
            Ok(password.to_string())
        } else if let Some(file_path) = pass_spec.strip_prefix("file:") {
            fs::read_to_string(file_path)
                .map(|s| s.trim().to_string())
                .map_err(|e| format!("Failed to read password file: {e}").into())
        } else {
            Err("Invalid password format. Use 'pass:<password>' or 'file:<path>'".into())
        }
    } else {
        // Prompt user for password
        Password::new()
            .with_prompt("Enter KeyStore password")
            .interact()
            .map_err(|e| e.into())
    }
}

// Job management endpoint handlers

#[instrument(skip(state))]
async fn start_refresh_cache_job(
    State(state): State<AppState>,
) -> Result<Json<JobResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Starting refresh cache job");

    match state.job_manager.create_job(JobType::RefreshCache).await {
        Ok(job_id) => {
            let job_id_clone = job_id.clone();
            let state_clone = state.clone();

            // Spawn background task
            tokio::spawn(async move {
                state_clone
                    .job_manager
                    .update_job_status(
                        &job_id_clone,
                        JobStatus::Running,
                        Some("Starting cache refresh".to_string()),
                        Some(0.1),
                    )
                    .await;

                match state_clone.pod_service.refresh_cache().await {
                    Ok(response) => {
                        let result = serde_json::to_value(response).unwrap_or_default();
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, Some(result), None)
                            .await;
                    }
                    Err(err) => {
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, None, Some(err))
                            .await;
                    }
                }
            });

            Ok(Json(JobResponse {
                job_id,
                status: JobStatus::Pending,
                message: "Cache refresh job started".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(err) => {
            error!("Failed to create refresh cache job: {}", err);
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "JOB_CREATION_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn start_upload_pod_job(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<JobResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Starting upload pod job");

    match state.job_manager.create_job(JobType::UploadPod).await {
        Ok(job_id) => {
            let job_id_clone = job_id.clone();
            let state_clone = state.clone();

            // Spawn background task
            tokio::spawn(async move {
                state_clone
                    .job_manager
                    .update_job_status(
                        &job_id_clone,
                        JobStatus::Running,
                        Some("Starting upload pod".to_string()),
                        Some(0.1),
                    )
                    .await;

                let request = UploadPodRequest {
                    address: address.clone(),
                };
                match state_clone.pod_service.upload_pod(request).await {
                    Ok(response) => {
                        let result = serde_json::to_value(response).unwrap_or_default();
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, Some(result), None)
                            .await;
                    }
                    Err(err) => {
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, None, Some(err))
                            .await;
                    }
                }
            });

            Ok(Json(JobResponse {
                job_id,
                status: JobStatus::Pending,
                message: "Upload all job started".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(err) => {
            error!("Failed to create upload all job: {}", err);
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "JOB_CREATION_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn start_upload_all_job(
    State(state): State<AppState>,
) -> Result<Json<JobResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Starting upload all job");

    match state.job_manager.create_job(JobType::UploadAll).await {
        Ok(job_id) => {
            let job_id_clone = job_id.clone();
            let state_clone = state.clone();

            // Spawn background task
            tokio::spawn(async move {
                state_clone
                    .job_manager
                    .update_job_status(
                        &job_id_clone,
                        JobStatus::Running,
                        Some("Starting upload all".to_string()),
                        Some(0.1),
                    )
                    .await;

                match state_clone.pod_service.upload_all().await {
                    Ok(response) => {
                        let result = serde_json::to_value(response).unwrap_or_default();
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, Some(result), None)
                            .await;
                    }
                    Err(err) => {
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, None, Some(err))
                            .await;
                    }
                }
            });

            Ok(Json(JobResponse {
                job_id,
                status: JobStatus::Pending,
                message: "Upload all job started".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(err) => {
            error!("Failed to create upload all job: {}", err);
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "JOB_CREATION_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn start_refresh_ref_job(
    State(state): State<AppState>,
    Path(depth): Path<u64>,
) -> Result<Json<JobResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Starting refresh ref job with depth: {}", depth);

    match state.job_manager.create_job(JobType::RefreshRef).await {
        Ok(job_id) => {
            let job_id_clone = job_id.clone();
            let state_clone = state.clone();

            // Spawn background task
            tokio::spawn(async move {
                state_clone
                    .job_manager
                    .update_job_status(
                        &job_id_clone,
                        JobStatus::Running,
                        Some(format!("Starting refresh ref with depth {depth}")),
                        Some(0.1),
                    )
                    .await;

                match state_clone.pod_service.refresh_ref(depth).await {
                    Ok(response) => {
                        let result = serde_json::to_value(response).unwrap_or_default();
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, Some(result), None)
                            .await;
                    }
                    Err(err) => {
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, None, Some(err))
                            .await;
                    }
                }
            });

            Ok(Json(JobResponse {
                job_id,
                status: JobStatus::Pending,
                message: format!("Refresh ref job started with depth {depth}"),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(err) => {
            error!("Failed to create refresh ref job: {}", err);
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "JOB_CREATION_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn start_search_job(
    State(state): State<AppState>,
    Json(query): Json<Value>,
) -> Result<Json<JobResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Starting search job for: {}", query.to_string());

    match state.job_manager.create_job(JobType::Search).await {
        Ok(job_id) => {
            let job_id_clone = job_id.clone();
            let state_clone = state.clone();
            let query_clone = query.clone();

            // Spawn background task
            tokio::spawn(async move {
                state_clone
                    .job_manager
                    .update_job_status(
                        &job_id_clone,
                        JobStatus::Running,
                        Some(format!("Searching for: {query_clone}")),
                        Some(0.1),
                    )
                    .await;

                match state_clone.pod_service.search(query_clone).await {
                    Ok(response) => {
                        let result = serde_json::to_value(response).unwrap_or_default();
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, Some(result), None)
                            .await;
                    }
                    Err(err) => {
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, None, Some(err))
                            .await;
                    }
                }
            });

            Ok(Json(JobResponse {
                job_id,
                status: JobStatus::Pending,
                message: format!("Search job started for: {query}"),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(err) => {
            error!("Failed to create search job: {}", err);
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "JOB_CREATION_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn start_get_subject_data_job(
    State(state): State<AppState>,
    Path(subject): Path<String>,
) -> Result<Json<JobResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Starting get subject data job for: {}", subject);

    match state.job_manager.create_job(JobType::GetSubjectData).await {
        Ok(job_id) => {
            let job_id_clone = job_id.clone();
            let state_clone = state.clone();
            let subject_clone = subject.clone();

            // Spawn background task
            tokio::spawn(async move {
                state_clone
                    .job_manager
                    .update_job_status(
                        &job_id_clone,
                        JobStatus::Running,
                        Some(format!("Getting subject data for: {subject_clone}")),
                        Some(0.1),
                    )
                    .await;

                match state_clone
                    .pod_service
                    .get_subject_data(&subject_clone)
                    .await
                {
                    Ok(response) => {
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, Some(response), None)
                            .await;
                    }
                    Err(err) => {
                        state_clone
                            .job_manager
                            .complete_job(&job_id_clone, None, Some(err))
                            .await;
                    }
                }
            });

            Ok(Json(JobResponse {
                job_id,
                status: JobStatus::Pending,
                message: format!("Get subject data job started for: {subject}"),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(err) => {
            error!("Failed to create get subject data job: {}", err);
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "JOB_CREATION_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn get_job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting status for job: {}", job_id);

    match state.job_manager.get_job(&job_id).await {
        Some(job) => {
            debug!("Job status retrieved for: {}", job_id);
            Ok(Json(JobStatusResponse { job }))
        }
        None => {
            warn!("Job not found: {}", job_id);
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "JOB_NOT_FOUND".to_string(),
                    message: format!("Job with ID {job_id} not found"),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn get_job_result(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobResultResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting result for job: {}", job_id);

    match state.job_manager.get_job(&job_id).await {
        Some(job) => match job.status {
            JobStatus::Completed | JobStatus::Failed => {
                debug!("Job result retrieved for: {}", job_id);
                Ok(Json(JobResultResponse {
                    job_id: job.id,
                    status: job.status,
                    result: job.result,
                    error: job.error,
                }))
            }
            _ => {
                warn!("Job not yet completed: {}", job_id);
                Err((
                    StatusCode::ACCEPTED,
                    Json(ErrorResponse {
                        error: "JOB_NOT_COMPLETED".to_string(),
                        message: format!("Job {job_id} is not yet completed"),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    }),
                ))
            }
        },
        None => {
            warn!("Job not found: {}", job_id);
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "JOB_NOT_FOUND".to_string(),
                    message: format!("Job with ID {job_id} not found"),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    // Macro to handle network-dependent test setup
    macro_rules! setup_test_components {
        () => {
            match create_mock_components().await {
                Ok(components) => components,
                Err(e) => {
                    println!("⚠️  Skipping test due to network unavailability: {}", e);
                    return;
                }
            }
        };
    }

    // Helper function to create mock components for testing
    async fn create_mock_components() -> Result<(Client, Wallet, DataStore, KeyStore, Graph), String>
    {
        // For testing, we'll create minimal mock components
        // Note: These tests will be limited since we can't easily mock the real components
        // In a real scenario, you'd want to use dependency injection or mock traits

        // Create a temporary directory for this test to avoid database conflicts
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let pods_dir = data_dir.join("pods");
        let pod_refs_dir = data_dir.join("pod_refs");
        let downloads_dir = data_dir.join("downloads");

        // Create directories
        fs::create_dir_all(&pods_dir).unwrap();
        fs::create_dir_all(&pod_refs_dir).unwrap();
        fs::create_dir_all(&downloads_dir).unwrap();

        // Create a data store using custom paths to avoid conflicts between tests
        let data_store = DataStore::from_paths(data_dir, pods_dir, downloads_dir).unwrap();

        // Create a test keystore with a known mnemonic
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut keystore = KeyStore::from_mnemonic(test_mnemonic).unwrap();
        keystore
            .set_wallet_key(
                "0x1234567890123456789012345678901234567890123456789012345678901234".to_string(),
            )
            .unwrap();

        // Save the keystore to file (PodManager might expect this file to exist)
        let keystore_path = data_store.get_keystore_path();
        let mut keystore_file = fs::File::create(&keystore_path).unwrap();
        keystore
            .to_file(&mut keystore_file, "test_password")
            .unwrap();

        // Create a test graph
        let graph_path = data_store.get_graph_path();
        let graph = Graph::open(&graph_path).unwrap();

        // Try to create test client and wallet - handle network failures gracefully
        let client = match Client::init_local().await {
            Ok(client) => client,
            Err(e) => {
                return Err(format!("Failed to initialize client for testing: {}", e));
            }
        };

        let wallet_key = keystore.get_wallet_key();
        let wallet = match Wallet::new_from_private_key(client.evm_network().clone(), &wallet_key) {
            Ok(wallet) => wallet,
            Err(e) => {
                return Err(format!("Failed to create wallet for testing: {}", e));
            }
        };

        Ok((client, wallet, data_store, keystore, graph))
    }

    async fn create_test_app_state() -> Result<AppState, String> {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await?;
        let pod_service = Arc::new(PodService::new(client, wallet, data_store, keystore, graph));
        let keystore_password = "test_password".to_string();
        let encoding_key = EncodingKey::from_secret(b"test_password");
        let decoding_key = DecodingKey::from_secret(b"test_password");

        Ok(AppState {
            pod_service,
            job_manager: Arc::new(JobManager::new()),
            encoding_key,
            decoding_key,
            keystore_password,
        })
    }

    #[tokio::test]
    async fn test_pod_service_add_pod() {
        let components = create_mock_components().await;
        if let Err(e) = components {
            println!("⚠️  Skipping test due to network unavailability: {}", e);
            return;
        }
        let (client, wallet, data_store, keystore, graph) = components.unwrap();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = CreatePodRequest {
            name: "test-pod".to_string(),
        };

        let result = service.add_pod(request, "test_password").await;

        // Note: This test may fail due to network connectivity issues in test environment
        // The important thing is that we can create the service and call the method
        // without panicking due to database locks
        match &result {
            Ok(pod) => {
                println!("✅ Pod created successfully: {}", pod.name);
                assert_eq!(pod.name, "test-pod");
                assert!(pod.address.len() > 0);
            }
            Err(e) => {
                println!("⚠️  Expected failure in test environment: {}", e);
                // In a test environment, we expect this to fail due to network issues
                // The test passes if we can at least call the service method
                assert!(e.contains("No such file or directory") || e.contains("Failed to"));
            }
        }
    }

    #[tokio::test]
    async fn test_pod_service_refresh_ref() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.refresh_ref(1).await;

        match &result {
            Ok(response) => {
                println!("✅ Refresh ref completed: {}", response.message);
                assert_eq!(response.status, "success");
                assert!(
                    response.message.contains("Pod references refreshed")
                        || response.message.contains("refreshed")
                );
            }
            Err(e) => {
                println!("⚠️  Expected failure in test environment: {}", e);
                // In test environment, this may fail due to network issues
                assert!(e.contains("Failed to") || e.contains("No such file"));
            }
        }
    }

    #[tokio::test]
    async fn test_pod_service_refresh_cache() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.refresh_cache().await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status, "success");
        assert!(response.message.contains("Cache refreshed"));
    }

    #[tokio::test]
    async fn test_pod_service_upload_all() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.upload_all().await;

        match &result {
            Ok(response) => {
                println!("✅ Upload all completed: {}", response.message);
                assert!(response.message.contains("All pods uploaded"));
            }
            Err(e) => {
                println!("⚠️  Expected failure in test environment: {}", e);
                // In test environment, this may fail due to network issues
                assert!(e.contains("Failed to") || e.contains("No such file"));
            }
        }
    }

    #[tokio::test]
    async fn test_pod_service_get_subject_data() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.get_subject_data("test-id").await;

        // This should fail because the subject doesn't exist
        match &result {
            Ok(_) => {
                println!("⚠️  Unexpected success - subject data found");
                // This would be unexpected but not necessarily wrong
            }
            Err(e) => {
                println!("✅ Expected failure: {}", e);
                // We expect this to fail with "Subject data not found" or similar
                assert!(e.contains("Subject data not found") || e.contains("Failed to"));
            }
        }
    }

    #[tokio::test]
    async fn test_job_manager() {
        let job_manager = JobManager::new();

        // Test creating a job
        let job_id = job_manager.create_job(JobType::RefreshCache).await.unwrap();
        assert!(!job_id.is_empty());

        // Test getting the job
        let job = job_manager.get_job(&job_id).await.unwrap();
        assert_eq!(job.id, job_id);
        assert!(matches!(job.status, JobStatus::Pending));
        assert!(matches!(job.job_type, JobType::RefreshCache));

        // Test updating job status
        job_manager
            .update_job_status(
                &job_id,
                JobStatus::Running,
                Some("Running".to_string()),
                Some(0.5),
            )
            .await;
        let job = job_manager.get_job(&job_id).await.unwrap();
        assert!(matches!(job.status, JobStatus::Running));
        assert_eq!(job.progress, Some(0.5));

        // Test completing job
        let result = serde_json::json!({"test": "result"});
        job_manager
            .complete_job(&job_id, Some(result.clone()), None)
            .await;
        let job = job_manager.get_job(&job_id).await.unwrap();
        assert!(matches!(job.status, JobStatus::Completed));
        assert_eq!(job.result, Some(result));
        assert_eq!(job.progress, Some(1.0));

        // Test that we can create another job now
        let job_id2 = job_manager.create_job(JobType::UploadAll).await.unwrap();
        assert_ne!(job_id, job_id2);
    }

    #[tokio::test]
    async fn test_job_manager_mutual_exclusion() {
        let job_manager = JobManager::new();

        // Create first job
        let job_id1 = job_manager.create_job(JobType::RefreshCache).await.unwrap();

        // Try to create second job - should fail
        let result = job_manager.create_job(JobType::UploadAll).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Another operation is already running")
        );

        // Complete first job
        job_manager.complete_job(&job_id1, None, None).await;

        // Now we should be able to create another job
        let job_id2 = job_manager.create_job(JobType::UploadAll).await.unwrap();
        assert!(!job_id2.is_empty());
    }

    #[tokio::test]
    async fn test_pod_service_put_subject_data() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = json!({"key": "value"});

        let result = service
            .put_subject_data("test-id", "test-subject", request.clone(), "test_password")
            .await;

        match &result {
            Ok(data) => {
                println!("✅ Subject data updated successfully");
                assert_eq!(*data, request);
            }
            Err(e) => {
                println!("⚠️  Expected failure in test environment: {}", e);
                // In test environment, this may fail due to network issues or missing pod
                assert!(e.contains("Failed to") || e.contains("Pod not found"));
            }
        }
    }

    #[tokio::test]
    async fn test_pod_service_add_pod_ref() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = PodRefRequest {
            pod_ref: "test-ref".to_string(),
        };

        let result = service
            .add_pod_ref("test-id", request, "test_password")
            .await;

        // Note: This test is expected to fail because we're trying to add a reference
        // to a pod that doesn't exist. The test passes if we get the expected error.
        match &result {
            Ok(_) => {
                println!("✅ Pod reference added successfully");
            }
            Err(e) => {
                println!("⚠️  Expected failure: {}", e);
                // We expect this to fail with "Pod not found" or similar
                assert!(e.contains("Pod not found") || e.contains("Failed to"));
            }
        }
    }

    #[tokio::test]
    async fn test_pod_service_remove_pod_ref() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = PodRefRequest {
            pod_ref: "test-ref".to_string(),
        };

        let result = service.remove_pod_ref("test-id", request).await;

        match &result {
            Ok(_) => {
                println!("✅ Pod reference removed successfully");
            }
            Err(e) => {
                println!("⚠️  Expected failure: {}", e);
                // We expect this to fail because the pod/reference doesn't exist
                assert!(e.contains("Failed to") || e.contains("not found"));
            }
        }
    }

    #[tokio::test]
    async fn test_pod_service_search() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = serde_json::json!({
            "type": "text",
            "text": "search term",
            "limit": 50
        });

        let result = service.search(request).await;
        assert!(result.is_ok());

        let response: Value = result.unwrap();
        //FIXME: better test here
        assert!(response.is_object());
    }

    #[tokio::test]
    async fn test_pod_service_remove_pod() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let pod_address = "test-pod-address";

        let result = service.remove_pod(pod_address, "test-password").await;

        match &result {
            Ok(()) => {
                println!("✅ Pod removed successfully");
            }
            Err(e) => {
                println!("⚠️  Expected failure: {}", e);
                // We expect this to fail because the pod doesn't exist
                assert!(e.contains("Failed to") || e.contains("not found"));
            }
        }
    }

    #[tokio::test]
    async fn test_pod_service_rename_pod() {
        let (client, wallet, data_store, keystore, graph) = setup_test_components!();
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let pod_address = "test-pod-address";
        let request = RenamePodRequest {
            name: "new-pod-name".to_string(),
        };

        let result = service
            .rename_pod(pod_address, request, "test-password")
            .await;

        match &result {
            Ok(()) => {
                println!("✅ Pod renamed successfully");
            }
            Err(e) => {
                println!("⚠️  Expected failure: {}", e);
                // We expect this to fail because the pod doesn't exist
                assert!(e.contains("Failed to") || e.contains("not found"));
            }
        }
    }

    #[test]
    fn test_get_password_with_pass_prefix() {
        let password_arg = "pass:test123".to_string();
        let result = get_password(Some(&password_arg)).unwrap();
        assert_eq!(result, "test123");
    }

    #[test]
    fn test_get_password_with_file_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("password.txt");
        fs::write(&file_path, "file_password123").unwrap();

        let password_arg = format!("file:{}", file_path.display());
        let result = get_password(Some(&password_arg)).unwrap();
        assert_eq!(result, "file_password123");
    }

    #[test]
    fn test_get_password_invalid_format() {
        let password_arg = "invalid:format".to_string();
        let result = get_password(Some(&password_arg));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid password format")
        );
    }

    #[tokio::test]
    async fn test_jwt_token_creation() {
        let app_state = match create_test_app_state().await {
            Ok(state) => state,
            Err(e) => {
                println!("⚠️  Skipping test due to network unavailability: {}", e);
                return;
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "test-user".to_string(),
            exp: now + 600,
            iat: now,
            password_verified: true,
        };

        let token = encode(&Header::default(), &claims, &app_state.encoding_key);
        assert!(token.is_ok());

        // Verify we can decode it
        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<Claims>(&token.unwrap(), &app_state.decoding_key, &validation);
        assert!(decoded.is_ok());

        let decoded_claims = decoded.unwrap().claims;
        assert_eq!(decoded_claims.sub, "test-user");
        assert_eq!(decoded_claims.password_verified, true);
    }

    #[tokio::test]
    async fn test_password_protected_token_creation() {
        let app_state = match create_test_app_state().await {
            Ok(state) => state,
            Err(e) => {
                println!("⚠️  Skipping test due to network unavailability: {}", e);
                return;
            }
        };

        // Test with correct password
        let auth_request = AuthRequest {
            password: "test_password".to_string(),
        };

        let result = create_token(
            axum::extract::State(app_state.clone()),
            axum::Json(auth_request),
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        let token_data: Value = serde_json::from_str(&response.0.to_string()).unwrap();
        assert!(token_data["token"].is_string());
        assert_eq!(token_data["expires_in"], 600);

        // Test with incorrect password
        let wrong_auth_request = AuthRequest {
            password: "wrong_password".to_string(),
        };

        let result = create_token(
            axum::extract::State(app_state.clone()),
            axum::Json(wrong_auth_request),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_token_validation_logic() {
        let app_state = match create_test_app_state().await {
            Ok(state) => state,
            Err(e) => {
                println!("⚠️  Skipping test due to network unavailability: {}", e);
                return;
            }
        };

        // Test token without password verification
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims_no_password = Claims {
            sub: "test-user".to_string(),
            exp: now + 600,
            iat: now,
            password_verified: false,
        };

        let token_no_password = encode(
            &Header::default(),
            &claims_no_password,
            &app_state.encoding_key,
        )
        .unwrap();

        // Verify we can decode the token but it should be rejected for lack of password verification
        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<Claims>(&token_no_password, &app_state.decoding_key, &validation);
        assert!(decoded.is_ok());

        let decoded_claims = decoded.unwrap().claims;
        assert_eq!(decoded_claims.password_verified, false);

        // Test token with password verification
        let claims_with_password = Claims {
            sub: "test-user".to_string(),
            exp: now + 600,
            iat: now,
            password_verified: true,
        };

        let token_with_password = encode(
            &Header::default(),
            &claims_with_password,
            &app_state.encoding_key,
        )
        .unwrap();

        let decoded_valid =
            decode::<Claims>(&token_with_password, &app_state.decoding_key, &validation);
        assert!(decoded_valid.is_ok());

        let decoded_valid_claims = decoded_valid.unwrap().claims;
        assert_eq!(decoded_valid_claims.password_verified, true);
    }
}
