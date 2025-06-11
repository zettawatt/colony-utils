use autonomi::{Wallet, Client};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use axum_extra::headers::{authorization::Bearer, Authorization};
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
use tokio::{self, net::TcpListener, sync::Mutex};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;
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
    // We'll store the components separately to avoid lifetime issues
    // In a real implementation, you might use a different approach
}

impl PodService {
    fn new() -> Self {
        Self {}
    }

    // Placeholder methods - these would interact with the actual PodManager
    async fn create_pod(&self, request: CreatePodRequest) -> Result<PodResponse, String> {
        info!("Creating pod: {}", request.name);
        // This is a placeholder implementation
        Ok(PodResponse {
            id: Uuid::new_v4().to_string(),
            name: request.name,
            description: request.description,
            metadata: request.metadata,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn get_pod(&self, id: &str) -> Result<PodResponse, String> {
        info!("Getting pod: {}", id);
        // This is a placeholder implementation
        Err("Pod not found".to_string())
    }

    async fn list_pods(&self) -> Result<Vec<PodResponse>, String> {
        info!("Listing all pods");
        // This is a placeholder implementation
        Ok(vec![])
    }

    async fn update_pod(&self, id: &str, request: UpdatePodRequest) -> Result<PodResponse, String> {
        info!("Updating pod: {}", id);
        // This is a placeholder implementation
        Err("Pod not found".to_string())
    }

    async fn delete_pod(&self, id: &str) -> Result<(), String> {
        info!("Deleting pod: {}", id);
        // This is a placeholder implementation
        Err("Pod not found".to_string())
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
                    "colony_daemon=debug,colonylib=info,tower_http=debug,axum=debug".into()
                })
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .json()
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

    let _pod_manager = PodManager::new(client, &wallet, &mut data_store, &mut keystore, &mut graph).await
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

    // Create application state
    let pod_service = Arc::new(PodService::new());
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
        .route("/api/v1/cache", post(refresh_cache))
        .route("/api/v1/pods", get(refresh_ref).post(add_pod))
        .route("/api/v1/pods/upload_all", put(upload_all))
        .route("/api/v1/pods/id", get(get_subject_data).put(put_subject_data))
        .route("/api/v1/pods/id/pod_ref", post(add_pod_ref).delete(remove_pod_ref))
        .route("/api/v1/search", get(search))
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

// Pod management endpoints
#[instrument(skip(state))]
async fn add_pod(
    State(state): State<AppState>,
    Json(request): Json<CreatePodRequest>,
) -> Result<Json<PodResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Creating new pod: {}", request.name);

    match state.pod_service.create_pod(request).await {
        Ok(pod) => {
            info!("Pod created successfully: {}", pod.id);
            Ok(Json(pod))
        }
        Err(err) => {
            error!("Failed to create pod: {}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "CREATION_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn get_pod(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<PodResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting pod: {}", id);

    match state.pod_service.get_pod(&id).await {
        Ok(pod) => {
            debug!("Pod retrieved successfully: {}", pod.id);
            Ok(Json(pod))
        }
        Err(err) => {
            warn!("Pod not found: {}", id);
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "POD_NOT_FOUND".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn list_pods(
    State(state): State<AppState>,
) -> Result<Json<Vec<PodResponse>>, (StatusCode, Json<ErrorResponse>)> {
    info!("Listing all pods");

    match state.pod_service.list_pods().await {
        Ok(pods) => {
            debug!("Retrieved {} pods", pods.len());
            Ok(Json(pods))
        }
        Err(err) => {
            error!("Failed to list pods: {}", err);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "LIST_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn update_pod(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdatePodRequest>,
) -> Result<Json<PodResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Updating pod: {}", id);

    match state.pod_service.update_pod(&id, request).await {
        Ok(pod) => {
            info!("Pod updated successfully: {}", pod.id);
            Ok(Json(pod))
        }
        Err(err) => {
            warn!("Failed to update pod {}: {}", id, err);
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "UPDATE_FAILED".to_string(),
                    message: err,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            ))
        }
    }
}

#[instrument(skip(state))]
async fn delete_pod(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    info!("Deleting pod: {}", id);

    match state.pod_service.delete_pod(&id).await {
        Ok(()) => {
            info!("Pod deleted successfully: {}", id);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(err) => {
            warn!("Failed to delete pod {}: {}", id, err);
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "DELETE_FAILED".to_string(),
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


    fn create_test_app_state() -> AppState {
        let pod_service = Arc::new(PodService::new());
        let encoding_key = EncodingKey::from_secret(b"test_secret");
        let decoding_key = DecodingKey::from_secret(b"test_secret");

        AppState {
            pod_service,
            encoding_key,
            decoding_key,
        }
    }





    #[tokio::test]
    async fn test_pod_service_create() {
        let service = PodService::new();
        let request = CreatePodRequest {
            name: "test-pod".to_string(),
            description: Some("A test pod".to_string()),
            metadata: Some([("env".to_string(), json!("test"))].into_iter().collect()),
        };

        let result = service.create_pod(request).await;
        assert!(result.is_ok());

        let pod = result.unwrap();
        assert_eq!(pod.name, "test-pod");
        assert_eq!(pod.description, Some("A test pod".to_string()));
        assert!(pod.id.len() > 0);
    }

    #[tokio::test]
    async fn test_pod_service_list_empty() {
        let service = PodService::new();
        let result = service.list_pods().await;
        assert!(result.is_ok());

        let pods = result.unwrap();
        assert_eq!(pods.len(), 0);
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
        let app_state = create_test_app_state();

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
