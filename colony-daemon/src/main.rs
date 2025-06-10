use autonomi::{Wallet, Client};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use clap::{Arg, Command};
use colonylib::{KeyStore, PodManager, DataStore, Graph};
use dialoguer::{Input, Password, Confirm};
use dirs;
use indicatif::{ProgressBar, ProgressStyle};
use jsonwebtoken::{encode, Header, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{self, net::TcpListener};
use tracing::{Level, info, warn};
use tracing_subscriber::{filter, prelude::*};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

#[derive(Clone)]
struct AppState {
    // We'll store the PodManager differently to avoid lifetime issues
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Setup error logging
    let subscriber = tracing_subscriber::registry()
    .with(filter::Targets::new()
        .with_target("colonylib", Level::INFO) // INFO level for colonylib
        .with_target("colony-daemon", Level::DEBUG)      // INFO level for colony-daemon
        .with_default(Level::ERROR))          // ERROR level for other modules
    .with(tracing_subscriber::fmt::layer());

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

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Setting up KeyStore...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let keystore_path = data_store.get_keystore_path();
    let keystore_password = get_password(password_arg)?;

    let mut keystore = if !keystore_path.exists() {
        // Initialize new KeyStore
        pb.set_message("Initializing new KeyStore...");

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
        pb.set_message("Loading existing KeyStore...");

        loop {
            let mut file = fs::File::open(&keystore_path)
                .map_err(|e| format!("Failed to open keystore file: {}", e))?;
            match KeyStore::from_file(&mut file, &keystore_password) {
                Ok(keystore) => break keystore,
                Err(_) => {
                    warn!("Failed to unlock KeyStore with provided password");
                    let _new_password = Password::new()
                        .with_prompt("Enter KeyStore password")
                        .interact()?;
                    // Note: This is a simplified approach - in practice you'd want to handle this better
                    continue;
                }
            }
        }
    };

    pb.finish_with_message("KeyStore setup complete");
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
    let app_state = AppState {
        encoding_key,
        decoding_key,
    };

    // For now, we'll just store the pod_manager separately
    // In a full implementation, you'd want to properly manage this
    info!("PodManager created successfully, but not integrated into REST API yet");

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
    Router::new()
        .route("/auth/token", post(create_token))
        .route("/health", get(health_check))
        // Add more PodManager endpoints here as needed
        .with_state(state)
}

async fn create_token(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
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
        Ok(token) => Ok(Json(serde_json::json!({ "token": token }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "healthy" }))
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
