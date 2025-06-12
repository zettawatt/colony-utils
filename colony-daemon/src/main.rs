use autonomi::{Wallet, Client};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::Json,
    routing::{get, post, put},
    Router,
};

use chrono;
use clap::{Arg, Command};
use colonylib::{KeyStore, PodManager, DataStore, Graph};
use dialoguer::{Input, Password, Confirm};
use dirs;
use indicatif::{ProgressBar, ProgressStyle};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{self, net::TcpListener};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, error, info, instrument, warn};

use tracing_subscriber::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

// Request/Response DTOs
#[derive(Debug, Serialize, Deserialize)]
struct CreatePodRequest {
    name: String,
    description: Option<String>,
    metadata: Option<HashMap<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdatePodRequest {
    name: Option<String>,
    description: Option<String>,
    metadata: Option<HashMap<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PodResponse {
    id: String,
    name: String,
    description: Option<String>,
    metadata: Option<HashMap<String, Value>>,
    created_at: String,
    updated_at: String,
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
    metadata: Option<HashMap<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubjectDataRequest {
    data: Value,
    metadata: Option<HashMap<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchRequest {
    query: String,
    filters: Option<HashMap<String, Value>>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
    total_count: usize,
    query: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchResult {
    id: String,
    title: String,
    description: Option<String>,
    score: f64,
    metadata: Option<HashMap<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheResponse {
    status: String,
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

    // PodManager method mappings - these would interact with the actual PodManager

    // Maps to PodManager::refresh_cache()
    async fn refresh_cache(&self) -> Result<CacheResponse, String> {
        info!("Refreshing cache");

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Use the PodManager
        podman.refresh_cache().await
            .map_err(|e| format!("Failed to refresh cache: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Cache refreshed successfully");

        Ok(CacheResponse {
            status: "success".to_string(),
            message: "Cache refreshed successfully".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    // Maps to PodManager::refresh_ref() - refreshes pod references
    async fn refresh_ref(&self, depth: u64) -> Result<RefreshResponse, String> {
        info!("Refreshing pod references to depth {}", depth);

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Use the PodManager
        podman.refresh_ref(depth).await
            .map_err(|e| format!("Failed to refresh pod references: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Pod references refreshed successfully");

        // For now, return empty vec as we'd need to implement pod listing functionality
        // In a full implementation, you'd query the refreshed data and convert to PodResponse
        Ok(RefreshResponse {
            status: "success".to_string(),
            message: "All pods refreshed successfully".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    // Maps to PodManager::add_pod()
    async fn add_pod(&self, request: CreatePodRequest) -> Result<PodResponse, String> {
        info!("Adding pod: {}", request.name);

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Use the PodManager
        let (pod_address, _pod_data) = podman.add_pod(&request.name).await
            .map_err(|e| format!("Failed to add pod: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Added pod {} with address {}", &request.name, &pod_address);

        Ok(PodResponse {
            id: pod_address,
            name: request.name,
            description: request.description,
            metadata: request.metadata,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    // Maps to PodManager::upload_all()
    async fn upload_all(&self) -> Result<UploadResponse, String> {
        info!("Uploading all pods");

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Use the PodManager
        podman.upload_all().await
            .map_err(|e| format!("Failed to upload all pods: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("All pods uploaded successfully");

        Ok(UploadResponse {
            message: "All pods uploaded successfully".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    // Maps to PodManager::get_subject_data()
    async fn get_subject_data(&self, id: &str) -> Result<Value, String> {
        info!("Getting subject data for: {}", id);

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Use the PodManager
        let subject_data = podman.get_subject_data(id).await
            .map_err(|e| format!("Failed to get subject data: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Subject data retrieved successfully for {}", id);

        // Parse the subject data string as JSON
        serde_json::from_str(&subject_data)
            .map_err(|e| format!("Failed to parse subject data as JSON: {}", e))
    }

    // Maps to PodManager::put_subject_data()
    async fn put_subject_data(&self, id: &str, subject: &str, request: SubjectDataRequest) -> Result<Value, String> {
        info!("Putting subject data for {} into pod {}", subject, id);

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Convert the JSON data to string for PodManager
        let data_string = serde_json::to_string(&request.data)
            .map_err(|e| format!("Failed to serialize data: {}", e))?;

        // Use the PodManager
        podman.put_subject_data(id, subject, &data_string).await
            .map_err(|e| format!("Failed to put subject data: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Subject data updated successfully for {} in pod {}", subject, id);

        Ok(request.data)
    }

    // Maps to PodManager::add_pod_ref()
    async fn add_pod_ref(&self, id: &str, request: PodRefRequest) -> Result<(), String> {
        info!("Adding pod reference for {}: {}", id, request.pod_ref);

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Use the PodManager
        podman.add_pod_ref(id, &request.pod_ref).await
            .map_err(|e| format!("Failed to add pod reference: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Pod reference added successfully for {}: {}", id, request.pod_ref);

        Ok(())
    }

    // Maps to PodManager::remove_pod_ref()
    async fn remove_pod_ref(&self, id: &str, pod_ref: &str) -> Result<(), String> {
        info!("Removing pod reference for {}: {}", id, pod_ref);

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Use the PodManager
        podman.remove_pod_ref(id, pod_ref).await
            .map_err(|e| format!("Failed to remove pod reference: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Pod reference removed successfully for {}: {}", id, pod_ref);

        Ok(())
    }

    // Maps to PodManager::search()
    async fn search(&self, request: SearchRequest) -> Result<SearchResponse, String> {
        info!("Searching for: {}", request.query);

        // Extract all data we need and drop all locks before any await
        let (client, wallet, mut data_store, mut keystore, mut graph) = {
            let client = self.client.lock().unwrap()
                .take()
                .ok_or("Client not initialized")?;
            let wallet = self.wallet.lock().unwrap()
                .take()
                .ok_or("Wallet not initialized")?;
            let data_store = self.data_store.lock().unwrap()
                .take()
                .ok_or("DataStore not initialized")?;
            let keystore = self.keystore.lock().unwrap()
                .take()
                .ok_or("KeyStore not initialized")?;
            let graph = self.graph.lock().unwrap()
                .take()
                .ok_or("Graph not initialized")?;
            (client, wallet, data_store, keystore, graph)
        };
        // All MutexGuards are dropped here

        // Now we can safely use async operations
        let mut podman = PodManager::new(
            client.clone(),
            &wallet,
            &mut data_store,
            &mut keystore,
            &mut graph
        ).await.map_err(|e| format!("Failed to create PodManager: {}", e))?;

        // Convert SearchRequest to the format expected by PodManager
        // PodManager::search expects a Value, so we'll convert the query string to JSON
        let search_query = serde_json::json!({
            "query": request.query,
            "filters": request.filters,
            "limit": request.limit
        });

        // Use the PodManager
        let search_results = podman.search(search_query).await
            .map_err(|e| format!("Failed to search: {}", e))?;

        // Put the components back
        {
            *self.client.lock().unwrap() = Some(client);
            *self.wallet.lock().unwrap() = Some(wallet);
            *self.data_store.lock().unwrap() = Some(data_store);
            *self.keystore.lock().unwrap() = Some(keystore);
            *self.graph.lock().unwrap() = Some(graph);
        }

        info!("Search completed for: {}", request.query);

        // Convert the search results to our SearchResponse format
        // This assumes search_results is a Value containing an array of results
        let results = if let Some(results_array) = search_results.as_array() {
            results_array.iter().enumerate().map(|(index, result)| SearchResult {
                // Convert each result Value to our SearchResult format
                // This is a simplified conversion - you might need to adjust based on actual result structure
                id: result.get("id").and_then(|v| v.as_str()).unwrap_or(&format!("result_{}", index)).to_string(),
                title: result.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled").to_string(),
                description: result.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
                score: result.get("score").and_then(|v| v.as_f64()).unwrap_or(1.0),
                metadata: result.get("metadata").and_then(|v| v.as_object()).map(|obj| {
                    obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                }),
            }).collect()
        } else {
            vec![]
        };

        let total_count = results.len();

        Ok(SearchResponse {
            results,
            total_count,
            query: request.query,
        })
    }


}

#[derive(Clone)]
struct AppState {
    pod_service: Arc<PodService>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Setup enhanced logging with structured output
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    "colony_daemon=debug,colonylib=debug,tower_http=debug,axum=debug".into()
                })
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                //.json()
        );

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Starting colony-daemon");

    // Parse command line arguments
    let matches = Command::new("colony-daemon")
        .version("0.1.0")
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
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Setting up DataStore...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let mut data_store = if matches.get_one::<String>("data").is_none() {
        // Create a new DataStore instance with the DataStore::create method()
        DataStore::create().map_err(|e| format!("Failed to create DataStore: {}", e))?
    } else {
        // Create a new DataStore instance with the DataStore::from_paths() method
        let pods_dir = data_dir.join("pods");
        let pod_refs_dir = data_dir.join("pod_refs");
        let downloads_dir = dirs::download_dir()
            .ok_or("Could not determine downloads directory")?;

        DataStore::from_paths(
            data_dir.clone(),
            pods_dir,
            pod_refs_dir,
            downloads_dir,
        ).map_err(|e| format!("Failed to create DataStore from paths: {}", e))?
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
            // Generate new mnemonic (this would need to be implemented in colonylib)
            // For now, prompt user to enter one
            Input::<String>::new()
                .with_prompt("Enter a BIP39 12-word mnemonic")
                .interact_text()?
        } else {
            Input::<String>::new()
                .with_prompt("Enter your existing BIP39 12-word mnemonic")
                .interact_text()?
        };

        // Create KeyStore from mnemonic
        let mut keystore = KeyStore::from_mnemonic(&mnemonic)
            .map_err(|e| format!("Failed to create KeyStore from mnemonic: {}", e))?;

        // Prompt for Ethereum wallet private key
        let wallet_key = Input::<String>::new()
            .with_prompt("Enter your Ethereum wallet private key")
            .interact_text()?;

        // Set wallet key
        keystore.set_wallet_key(wallet_key)
            .map_err(|e| format!("Failed to set wallet key: {}", e))?;

        // Save KeyStore to file
        let mut file = fs::File::create(&keystore_path)
            .map_err(|e| format!("Failed to create keystore file: {}", e))?;
        keystore.to_file(&mut file, &keystore_password)
            .map_err(|e| format!("Failed to save KeyStore: {}", e))?;

        keystore
    } else {
        // Load existing KeyStore
        loop {
            let mut file = fs::File::open(&keystore_path)
                .map_err(|e| format!("Failed to open keystore file: {}", e))?;
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
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Setting up Graph...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let graph_path = data_store.get_graph_path();
    let mut graph = Graph::open(&graph_path)
        .map_err(|e| format!("Failed to open Graph: {}", e))?;

    pb.finish_with_message("Graph setup complete");
    info!("Graph initialized at: {:?}", graph_path);

    /////////////////////////////////
    // Autonomi Connection step
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Connecting to Autonomi network...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let client = init_client(network.to_string()).await;

    let wallet_key = keystore.get_wallet_key();
    let wallet = Wallet::new_from_private_key(client.evm_network().clone(), &wallet_key)
        .map_err(|e| format!("Failed to create wallet: {}", e))?;

    pb.finish_with_message("Connected to Autonomi network");
    info!("Connected to {} network", network);

    /////////////////////////////////
    // PodManager setup step
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Setting up PodManager...");
    pb.enable_steady_tick(Duration::from_millis(100));

    // Test PodManager creation to ensure components are compatible
    let _pod_manager = PodManager::new(client.clone(), &wallet, &mut data_store, &mut keystore, &mut graph).await
        .map_err(|e| format!("Failed to create PodManager: {}", e))?;

    pb.finish_with_message("PodManager setup complete");
    info!("PodManager initialized successfully");

    /////////////////////////////////
    // start REST server
    /////////////////////////////////

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Starting REST server...");
    pb.enable_steady_tick(Duration::from_millis(100));

    // Create JWT keys from keystore password
    let encoding_key = EncodingKey::from_secret(keystore_password.as_bytes());
    let decoding_key = DecodingKey::from_secret(keystore_password.as_bytes());

    // Create application state with components
    let pod_service = Arc::new(PodService::new(client, wallet, data_store, keystore, graph));
    let app_state = AppState {
        pod_service,
        encoding_key,
        decoding_key,
    };

    info!("PodManager created successfully and integrated into REST API");

    // Create router with all endpoints
    let app = create_router(app_state);

    // Create socket address
    let addr = format!("{}:{}", listen_ip, port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

    pb.finish_with_message("REST server started");
    info!("Server listening on {}", addr);

    // Start the server
    axum::serve(listener, app).await
        .map_err(|e| format!("Server error: {}", e))?;

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
        .route("/auth/token", post(create_token))
        .route("/health", get(health_check));

    // Protected routes (authentication required)
    let protected_routes = Router::new()
        .route("/api/v1/cache", put(upload_all).post(refresh_cache))
        .route("/api/v1/cache/{depth}", post(refresh_ref))
        .route("/api/v1/pods", post(add_pod))
        .route("/api/v1/pods/{pod}/{subject}", put(put_subject_data))
        .route("/api/v1/pods/{pod}/pod_ref", post(add_pod_ref).delete(remove_pod_ref))
        .route("/api/v1/search", get(search))
        .route("/api/v1/search/subject/{subject}", get(get_subject_data))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Combine routes with middleware
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
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
            debug!("Valid token for user: {}", token_data.claims.sub);
            Ok(next.run(request).await)
        }
        Err(err) => {
            warn!("Invalid token: {}", err);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// Authentication endpoints
#[instrument(skip(state))]
async fn create_token(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: "colony-daemon".to_string(),
        exp: now + 600, // 10 minutes
        iat: now,
    };

    match encode(&Header::default(), &claims, &state.encoding_key) {
        Ok(token) => {
            info!("JWT token created successfully");
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
async fn refresh_cache(State(state): State<AppState>) -> Result<Json<CacheResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Refreshing cache");

    match state.pod_service.refresh_cache().await {
        Ok(response) => {
            info!("Cache refreshed successfully");
            Ok(Json(response))
        }
        Err(err) => {
            error!("Failed to refresh cache: {}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "CACHE_REFRESH_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn refresh_ref(
    State(state): State<AppState>,
    Path(depth): Path<u64>,
) -> Result<Json<RefreshResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Refreshing pod references from depth {}", depth);

    match state.pod_service.refresh_ref(depth).await {
        Ok(pods) => {
            debug!("Retrieved pod references up to depth {}", depth);
            Ok(Json(pods))
        }
        Err(err) => {
            error!("Failed to refresh pod references: {}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "REFRESH_REF_FAILED".to_string(),
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

    match state.pod_service.add_pod(request).await {
        Ok(pod) => {
            info!("Pod added successfully: {}", pod.id);
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
async fn upload_all(State(state): State<AppState>) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Uploading all pods");

    match state.pod_service.upload_all().await {
        Ok(response) => {
            info!("Upload completed");
            Ok(Json(response))
        }
        Err(err) => {
            error!("Failed to upload all pods: {}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "UPLOAD_ALL_FAILED".to_string(),
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
    Path(pod): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting subject data for: {}", pod);

    match state.pod_service.get_subject_data(&pod).await {
        Ok(data) => {
            debug!("Subject data retrieved successfully for: {}", pod);
            Ok(Json(data))
        }
        Err(err) => {
            warn!("Subject data not found for: {}", pod);
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
    Path(pod): Path<String>,
    Path(subject): Path<String>,
    Json(request): Json<SubjectDataRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Putting subject data for {} in pod {}", subject, pod);

    match state.pod_service.put_subject_data(&pod, &subject, request).await {
        Ok(data) => {
            info!("Subject data updated successfully for {} in pod {}", subject, pod);
            Ok(Json(data))
        }
        Err(err) => {
            error!("Failed to update subject data for {} in pod {}: {}", subject, pod, err);
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

    match state.pod_service.add_pod_ref(&id, request).await {
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
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let pod_ref = match params.get("pod_ref") {
        Some(pod_ref) => pod_ref,
        None => {
            warn!("Missing pod_ref parameter for remove_pod_ref");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "MISSING_PARAMETER".to_string(),
                    message: "pod_ref parameter is required".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ));
        }
    };

    info!("Removing pod reference for {}: {}", id, pod_ref);

    match state.pod_service.remove_pod_ref(&id, pod_ref).await {
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
async fn search(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<SearchResponse>, (StatusCode, Json<ErrorResponse>)> {
    let query = match params.get("q") {
        Some(query) => query.clone(),
        None => {
            warn!("Missing query parameter for search");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "MISSING_PARAMETER".to_string(),
                    message: "q parameter is required".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ));
        }
    };

    let limit = params.get("limit")
        .and_then(|l| l.parse::<usize>().ok());

    let search_request = SearchRequest {
        query: query.clone(),
        filters: None,
        limit,
    };

    info!("Searching for: {}", query);

    match state.pod_service.search(search_request).await {
        Ok(response) => {
            debug!("Search completed: {} results for query '{}'", response.total_count, query);
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
                .map_err(|e| format!("Failed to read password file: {}", e).into())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    // Helper function to create mock components for testing
    async fn create_mock_components() -> (Client, Wallet, DataStore, KeyStore, Graph) {
        // For testing, we'll create minimal mock components
        // Note: These tests will be limited since we can't easily mock the real components
        // In a real scenario, you'd want to use dependency injection or mock traits

        // Create a data store using the default create method
        let data_store = DataStore::create().unwrap();

        // Create a test keystore with a known mnemonic
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut keystore = KeyStore::from_mnemonic(test_mnemonic).unwrap();
        keystore.set_wallet_key("0x1234567890123456789012345678901234567890123456789012345678901234".to_string()).unwrap();

        // Create a test graph
        let graph_path = data_store.get_graph_path();
        let graph = Graph::open(&graph_path).unwrap();

        // Create test client and wallet
        let client = Client::init_local().await.unwrap();
        let wallet_key = keystore.get_wallet_key();
        let wallet = Wallet::new_from_private_key(client.evm_network().clone(), &wallet_key).unwrap();

        (client, wallet, data_store, keystore, graph)
    }

    async fn create_test_app_state() -> AppState {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let pod_service = Arc::new(PodService::new(client, wallet, data_store, keystore, graph));
        let encoding_key = EncodingKey::from_secret(b"test_secret");
        let decoding_key = DecodingKey::from_secret(b"test_secret");

        AppState {
            pod_service,
            encoding_key,
            decoding_key,
        }
    }





    #[tokio::test]
    async fn test_pod_service_add_pod() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = CreatePodRequest {
            name: "test-pod".to_string(),
            description: Some("A test pod".to_string()),
            metadata: Some([("env".to_string(), json!("test"))].into_iter().collect()),
        };

        let result = service.add_pod(request).await;
        assert!(result.is_ok());

        let pod = result.unwrap();
        assert_eq!(pod.name, "test-pod");
        assert_eq!(pod.description, Some("A test pod".to_string()));
        assert!(pod.id.len() > 0);
    }

    #[tokio::test]
    async fn test_pod_service_refresh_ref() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.refresh_ref(1).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status, "success");
        assert!(response.message.contains("Pod references refreshed"));
    }

    #[tokio::test]
    async fn test_pod_service_refresh_cache() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.refresh_cache().await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status, "success");
        assert!(response.message.contains("Cache refreshed"));
    }

    #[tokio::test]
    async fn test_pod_service_upload_all() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.upload_all().await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.message.contains("All pods uploaded"));
    }

    #[tokio::test]
    async fn test_pod_service_get_subject_data() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.get_subject_data("test-id").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Subject data not found");
    }

    #[tokio::test]
    async fn test_pod_service_put_subject_data() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = SubjectDataRequest {
            data: json!({"key": "value"}),
            metadata: None,
        };

        let result = service.put_subject_data("test-id", "test-subject",request).await;
        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data, json!({"key": "value"}));
    }

    #[tokio::test]
    async fn test_pod_service_add_pod_ref() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = PodRefRequest {
            pod_ref: "test-ref".to_string(),
            metadata: None,
        };

        let result = service.add_pod_ref("test-id", request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pod_service_remove_pod_ref() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let result = service.remove_pod_ref("test-id", "test-ref").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pod_service_search() {
        let (client, wallet, data_store, keystore, graph) = create_mock_components().await;
        let service = PodService::new(client, wallet, data_store, keystore, graph);
        let request = SearchRequest {
            query: "test query".to_string(),
            filters: None,
            limit: Some(10),
        };

        let result = service.search(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.query, "test query");
        assert_eq!(response.total_count, 0);
        assert_eq!(response.results.len(), 0);
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
        assert!(result.unwrap_err().to_string().contains("Invalid password format"));
    }

    #[tokio::test]
    async fn test_jwt_token_creation() {
        let app_state = create_test_app_state().await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "test-user".to_string(),
            exp: now + 600,
            iat: now,
        };

        let token = encode(&Header::default(), &claims, &app_state.encoding_key);
        assert!(token.is_ok());

        // Verify we can decode it
        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<Claims>(&token.unwrap(), &app_state.decoding_key, &validation);
        assert!(decoded.is_ok());

        let decoded_claims = decoded.unwrap().claims;
        assert_eq!(decoded_claims.sub, "test-user");
    }
}
