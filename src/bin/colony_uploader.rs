use anyhow::Result;

use clap::{Arg, Command};
use colored::*;
use dialoguer::Password;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use std::fs;
use std::path::Path;
use std::sync::Arc;

use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileUploadRequest {
    file_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobResponse {
    job_id: String,
    status: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobStatusResponse {
    job: JobInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobInfo {
    id: String,
    job_type: String,
    status: String,
    progress: Option<f64>,
    message: Option<String>,
    result: Option<Value>,
    error: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileResponse {
    file_path: String,
    address: String,
    size: u64,
    ant_cost: f64,
    gas_cost: f64,
    timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadStats {
    files_uploaded: u64,
    total_size: u64,
    total_cost_ant: f64,
    total_cost_eth: f64,
    successful_directories: u64,
    failed_directories: u64,
    total_time: std::time::Duration,
    initial_eth_balance: Option<f64>,
    final_eth_balance: Option<f64>,
}

impl Default for UploadStats {
    fn default() -> Self {
        Self {
            files_uploaded: 0,
            total_size: 0,
            total_cost_ant: 0.0,
            total_cost_eth: 0.0,
            successful_directories: 0,
            failed_directories: 0,
            total_time: std::time::Duration::from_secs(0),
            initial_eth_balance: None,
            final_eth_balance: None,
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    server: String,
    port: u16,
    threads: usize,
    keep_directories: bool,
    base_url: String,
}

impl Config {
    fn new(server: String, port: u16, threads: usize, keep_directories: bool) -> Self {
        let base_url = format!("http://{server}:{port}");
        Self {
            server,
            port,
            threads,
            keep_directories,
            base_url,
        }
    }
}

struct DirectoryProcessor {
    config: Config,
    client: Client,
    token: Arc<Mutex<String>>,
    stats: Arc<Mutex<UploadStats>>,
}

impl DirectoryProcessor {
    fn new(config: Config, client: Client, token: String) -> Self {
        Self {
            config,
            client,
            token: Arc::new(Mutex::new(token)),
            stats: Arc::new(Mutex::new(UploadStats::default())),
        }
    }

    async fn process_directory(&self, dir_path: &Path, pb: ProgressBar) -> Result<(), String> {
        pb.set_message("🔍 Analyzing directory...");

        // Read pod name
        let pod_name_file = dir_path.join("pod_name.txt");
        let pod_name = fs::read_to_string(&pod_name_file)
            .map_err(|e| format!("Failed to read pod_name.txt: {e}"))?
            .trim()
            .to_string();

        pb.set_message("📤 Uploading files to Autonomi...");

        // Find and upload all files
        let mut uploaded_files = Vec::new();
        let mut total_size = 0u64;

        // Upload main files (PDFs, EPUBs, etc.)
        for entry in fs::read_dir(dir_path).map_err(|e| format!("Failed to read directory: {e}"))? {
            let entry = entry.map_err(|e| format!("Failed to read entry: {e}"))?;
            let path = entry.path();

            if path.is_dir()
                && !path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("__")
            {
                // This is a file type directory (pdf, epub, txt, etc.)
                for file_entry in
                    fs::read_dir(&path).map_err(|e| format!("Failed to read subdirectory: {e}"))?
                {
                    let file_entry =
                        file_entry.map_err(|e| format!("Failed to read file entry: {e}"))?;
                    let file_path = file_entry.path();

                    if file_path.is_file()
                        && !file_path
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .ends_with(".json")
                    {
                        // Upload this file to Autonomi
                        let file_size = fs::metadata(&file_path)
                            .map_err(|e| format!("Failed to get file metadata: {e}"))?
                            .len();

                        let filename = file_path.file_name().unwrap().to_str().unwrap();
                        pb.set_message(format!("📤 Uploading {filename}..."));

                        // Upload to Autonomi using public file upload
                        match self.upload_file_to_autonomi(&file_path, Some(&pb)).await {
                            Ok(address) => {
                                pb.set_message(format!("✅ Uploaded {filename} -> {address}"));
                                uploaded_files.push(file_path.clone());
                                total_size += file_size;
                            }
                            Err(e) => {
                                return Err(format!(
                                    "Failed to upload {filename} to Autonomi: {e}"
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Upload thumbnail if it exists
        let thumbnail_path = dir_path.join("__ia_thumb.jpg");
        if thumbnail_path.exists() {
            let thumb_size = fs::metadata(&thumbnail_path)
                .map_err(|e| format!("Failed to get thumbnail metadata: {e}"))?
                .len();

            pb.set_message("🖼️ Uploading thumbnail...");

            match self
                .upload_file_to_autonomi(&thumbnail_path, Some(&pb))
                .await
            {
                Ok(address) => {
                    pb.set_message(format!("✅ Uploaded thumbnail -> {address}"));
                    uploaded_files.push(thumbnail_path);
                    total_size += thumb_size;
                }
                Err(e) => {
                    return Err(format!("Failed to upload thumbnail to Autonomi: {e}"));
                }
            }
        }

        pb.set_message("📝 Uploading metadata to colony...");

        // Process metadata files and upload to colony
        self.upload_metadata_to_colony(dir_path, &pod_name).await?;

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.files_uploaded += uploaded_files.len() as u64;
            stats.total_size += total_size;
            stats.successful_directories += 1;
            // TODO: Add actual cost calculation when Autonomi API is integrated
        }

        pb.set_message("✅ Complete");
        Ok(())
    }

    async fn upload_file_to_autonomi(
        &self,
        file_path: &Path,
        upload_pb: Option<&ProgressBar>,
    ) -> Result<String, String> {
        // Get fresh token for each request to avoid 401 errors
        let token = self.token.lock().await.clone();

        // Get file size for progress tracking
        let file_size = fs::metadata(file_path)
            .map_err(|e| format!("Failed to get file metadata: {e}"))?
            .len();

        let filename = file_path.file_name().unwrap().to_str().unwrap();

        // Create progress bar for this upload if one wasn't provided
        let pb = if let Some(existing_pb) = upload_pb {
            existing_pb.clone()
        } else {
            let pb = ProgressBar::new(100); // Use percentage for job progress
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {percent}% {msg}")
                .unwrap()
                .progress_chars("#>-"));
            pb.set_message(format!("📤 {filename}"));
            pb
        };

        pb.set_message(format!(
            "📤 Starting upload of {filename} ({file_size} bytes)..."
        ));

        // Start upload job - use absolute path to ensure colonyd can find the file
        let absolute_path = file_path
            .canonicalize()
            .map_err(|e| format!("Failed to get absolute path: {e}"))?;
        let full_path = absolute_path.to_string_lossy().to_string();

        let upload_request = FileUploadRequest {
            file_path: full_path,
        };

        let response = self
            .client
            .post(format!("{}/colony-0/file/upload", self.config.base_url))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .json(&upload_request)
            .send()
            .await
            .map_err(|e| format!("Failed to start upload job: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            pb.set_message(format!("❌ Upload failed: {error_text}"));
            return Err(format!("Upload job failed {status}: {error_text}"));
        }

        let job_response: JobResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse job response: {e}"))?;

        pb.set_message(format!("📤 Upload job started for {filename}..."));

        // Poll for job completion with progress updates
        self.wait_for_job_completion_with_progress(&job_response.job_id, &pb, filename)
            .await
    }

    async fn wait_for_job_completion_with_progress(
        &self,
        job_id: &str,
        pb: &ProgressBar,
        filename: &str,
    ) -> Result<String, String> {
        let token = self.token.lock().await.clone();
        let start_time = Instant::now();
        let mut last_progress = 0.0;

        loop {
            let response = self
                .client
                .get(format!("{}/colony-0/jobs/{}", self.config.base_url, job_id))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .map_err(|e| format!("Failed to check job status: {e}"))?;

            if !response.status().is_success() {
                pb.set_message(format!("❌ Failed to get job status for {filename}"));
                return Err(format!("Failed to get job status: {}", response.status()));
            }

            let job_status: JobStatusResponse = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse job status: {e}"))?;

            // Update progress if available
            if let Some(progress) = job_status.job.progress {
                let progress_percent = (progress * 100.0) as u64;
                pb.set_position(progress_percent);

                // Calculate estimated time remaining
                let elapsed = start_time.elapsed();
                if progress > 0.0 && progress > last_progress {
                    let estimated_total = elapsed.as_secs_f64() / progress;
                    let remaining = estimated_total - elapsed.as_secs_f64();

                    if remaining > 0.0 {
                        let remaining_str = if remaining > 60.0 {
                            format!("{:.1}m", remaining / 60.0)
                        } else {
                            format!("{remaining:.0}s")
                        };
                        pb.set_message(format!(
                            "📤 {} ({:.1}% - ETA: {})",
                            filename,
                            progress * 100.0,
                            remaining_str
                        ));
                    } else {
                        pb.set_message(format!("📤 {} ({:.1}%)", filename, progress * 100.0));
                    }
                } else {
                    pb.set_message(format!("📤 {} ({:.1}%)", filename, progress * 100.0));
                }
                last_progress = progress;
            } else {
                // No progress info, just show status
                pb.set_message(format!("📤 {} ({})", filename, job_status.job.status));
            }

            match job_status.job.status.as_str() {
                "completed" => {
                    pb.set_position(100);
                    if let Some(result) = job_status.job.result {
                        if let Some(file_response) = result.as_object() {
                            // Extract cost information and update stats
                            if let Some(ant_cost) =
                                file_response.get("ant_cost").and_then(|v| v.as_f64())
                            {
                                let mut stats = self.stats.lock().await;
                                stats.total_cost_ant += ant_cost;
                            }

                            if let Some(address) =
                                file_response.get("address").and_then(|v| v.as_str())
                            {
                                let elapsed = start_time.elapsed();
                                pb.set_message(format!(
                                    "✅ {} -> {} ({}s)",
                                    filename,
                                    address,
                                    elapsed.as_secs()
                                ));
                                return Ok(address.to_string());
                            }
                        }
                        pb.set_message(format!("❌ {filename} - No address in result"));
                        return Err("Job completed but no address in result".to_string());
                    }
                    pb.set_message(format!("❌ {filename} - No result"));
                    return Err("Job completed but no result".to_string());
                }
                "failed" => {
                    let error_msg = job_status
                        .job
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    pb.set_message(format!("❌ {filename} - {error_msg}"));
                    return Err(format!("Upload job failed: {error_msg}"));
                }
                "running" | "pending" => {
                    // Poll more frequently for better responsiveness
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
                _ => {
                    pb.set_message(format!(
                        "❌ {} - Unknown status: {}",
                        filename, job_status.job.status
                    ));
                    return Err(format!("Unknown job status: {}", job_status.job.status));
                }
            }
        }
    }

    async fn upload_metadata_to_colony(
        &self,
        dir_path: &Path,
        pod_name: &str,
    ) -> Result<(), String> {
        // Find all metadata.json files
        for entry in fs::read_dir(dir_path).map_err(|e| format!("Failed to read directory: {e}"))? {
            let entry = entry.map_err(|e| format!("Failed to read entry: {e}"))?;
            let path = entry.path();

            if path.is_dir()
                && !path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("__")
            {
                // Look for metadata files in this subdirectory
                for file_entry in
                    fs::read_dir(&path).map_err(|e| format!("Failed to read subdirectory: {e}"))?
                {
                    let file_entry =
                        file_entry.map_err(|e| format!("Failed to read file entry: {e}"))?;
                    let file_path = file_entry.path();

                    if file_path.is_file() {
                        let filename = file_path.file_name().unwrap().to_str().unwrap();
                        if filename == "metadata.json"
                            || filename.starts_with("metadata_") && filename.ends_with(".json")
                        {
                            // Read and upload this metadata
                            let metadata_content = fs::read_to_string(&file_path).map_err(|e| {
                                format!("Failed to read metadata file {filename}: {e}")
                            })?;

                            let metadata: Value =
                                serde_json::from_str(&metadata_content).map_err(|e| {
                                    format!("Failed to parse metadata JSON {filename}: {e}")
                                })?;

                            // Extract the subject (the @id field)
                            let subject =
                                metadata
                                    .get("@id")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        format!("No @id field found in metadata file {filename}")
                                    })?;

                            // Upload to colony via REST API
                            self.upload_subject_data(pod_name, subject, &metadata)
                                .await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn upload_subject_data(
        &self,
        pod_name: &str,
        subject: &str,
        data: &Value,
    ) -> Result<(), String> {
        let token = self.token.lock().await.clone();
        let encoded_pod_name = urlencoding::encode(pod_name);
        let encoded_subject = urlencoding::encode(subject);
        let url = format!(
            "{}/colony-0/pods/{}/{}",
            self.config.base_url, encoded_pod_name, encoded_subject
        );

        // Debug output
        println!("🔍 Uploading to URL: {url}");
        println!("🔍 Pod name: '{pod_name}'");
        println!("🔍 Subject: '{subject}'");

        let response = self
            .client
            .put(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .json(data)
            .send()
            .await
            .map_err(|e| format!("Failed to send request to colony: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!(
                "Colony API error {status}: {error_text} (URL: {url})"
            ));
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Command::new("colony_uploader")
        .version("0.1.1")
        .author("Chuck McClish")
        .about("🏛️ Colony uploader for Autonomi network")
        .arg(
            Arg::new("server")
                .short('s')
                .long("server")
                .value_name("SERVER")
                .help("Colonyd server location")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Colonyd port")
                .default_value("3000"),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("THREADS")
                .help("Number of uploader directories to process in parallel")
                .default_value("1"),
        )
        .arg(
            Arg::new("keep")
                .short('k')
                .long("keep")
                .help("Keep the uploader directories after processing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("directory")
                .value_name("DIRECTORY")
                .help("Directory containing uploader directories (default: colony_uploader)")
                .default_value("colony_uploader"),
        );

    let matches = app.get_matches();

    let server = matches.get_one::<String>("server").unwrap().clone();
    let port: u16 = matches
        .get_one::<String>("port")
        .unwrap()
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port number"))?;
    let threads: usize = matches
        .get_one::<String>("threads")
        .unwrap()
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid thread count"))?;
    let keep_directories = matches.get_flag("keep");
    let upload_dir = matches.get_one::<String>("directory").unwrap();

    let config = Config::new(server, port, threads, keep_directories);

    println!("{} {}", "🏛️".bold(), "Colony Uploader".bold().cyan());
    println!();
    println!(
        "{} {}:{}",
        "🌐 Server:".bold(),
        config.server.green(),
        config.port.to_string().green()
    );
    println!(
        "{} {}",
        "🧵 Threads:".bold(),
        config.threads.to_string().green()
    );
    println!("{} {}", "📁 Directory:".bold(), upload_dir.blue());
    println!();

    // Start timing from the beginning of the actual work
    let start_time = std::time::Instant::now();

    // Get password for colonyd
    let password = Password::new()
        .with_prompt("🔐 Enter colonyd password")
        .interact()?;

    // Initialize HTTP client
    let client = Client::new();

    // Authenticate with colonyd
    println!(
        "{} {}",
        "🔑".bold(),
        "Authenticating with colonyd...".yellow()
    );
    let auth_response = authenticate_with_colonyd(&client, &config, &password).await?;
    println!("{} {}", "✅".green(), "Authentication successful".green());

    // Start token refresh watchdog
    let token = Arc::new(Mutex::new(auth_response));
    let token_refresh = token.clone();
    let client_refresh = client.clone();
    let config_refresh = config.clone();
    let password_refresh = password.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(9 * 60)); // 9 minutes
        loop {
            interval.tick().await;
            match refresh_token(&client_refresh, &config_refresh, &password_refresh).await {
                Ok(new_token) => {
                    let mut token_guard = token_refresh.lock().await;
                    *token_guard = new_token;
                }
                Err(e) => {
                    eprintln!("{} Failed to refresh token: {}", "⚠️".yellow(), e);
                }
            }
        }
    });

    // Get initial wallet balance for accurate cost calculation
    let initial_balance = match get_wallet_balance(&client, &config, &token.lock().await).await {
        Ok(balance) => {
            println!("{} Initial wallet balance: {:.6} ETH", "💰".bold(), balance);
            Some(balance)
        }
        Err(e) => {
            eprintln!(
                "{} Warning: Could not get initial wallet balance: {}",
                "⚠️".yellow(),
                e
            );
            None
        }
    };

    // Scan for uploader directories
    println!(
        "{} {}",
        "🔍".bold(),
        "Scanning for uploader directories...".yellow()
    );
    let upload_path = Path::new(upload_dir);

    if !upload_path.exists() {
        return Err(anyhow::anyhow!(
            "Upload directory '{}' does not exist",
            upload_dir
        ));
    }

    let mut uploader_dirs = Vec::new();
    for entry in fs::read_dir(upload_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Check if this looks like an uploader directory (has pod_name.txt)
            let pod_name_file = path.join("pod_name.txt");
            if pod_name_file.exists() {
                uploader_dirs.push(path);
            }
        }
    }

    if uploader_dirs.is_empty() {
        println!(
            "{} {}",
            "ℹ️".blue(),
            "No uploader directories found".yellow()
        );
        return Ok(());
    }

    println!(
        "{} Found {} uploader directories",
        "📁".bold(),
        uploader_dirs.len().to_string().green()
    );
    println!();

    // Create progress display
    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new(uploader_dirs.len() as u64));
    main_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    main_pb.set_message("Processing directories...");

    // Create processor
    let processor = Arc::new(DirectoryProcessor::new(
        config.clone(),
        client.clone(),
        token.lock().await.clone(),
    ));

    // Create semaphore to limit concurrent operations
    let semaphore = Arc::new(Semaphore::new(config.threads));

    // Process directories concurrently
    let mut handles = Vec::new();
    let mut progress_bars = Vec::new();

    for dir_path in uploader_dirs {
        let dir_name = dir_path.file_name().unwrap().to_str().unwrap().to_string();

        // Create progress bar for this directory
        let pb = multi_progress.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.blue} {prefix} {msg}")
                .unwrap(),
        );
        pb.set_prefix(format!("⏳ {dir_name}"));
        pb.set_message("Pending...");
        progress_bars.push(pb.clone());

        let processor = processor.clone();
        let semaphore = semaphore.clone();
        let main_pb = main_pb.clone();
        let keep_directories = config.keep_directories;

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            pb.set_prefix(format!("🔄 {dir_name}"));
            pb.set_message("Processing...");

            let result = processor.process_directory(&dir_path, pb.clone()).await;

            match result {
                Ok(()) => {
                    pb.set_prefix(format!("✅ {dir_name}"));
                    pb.set_message("Success");
                    pb.finish();

                    // Delete directory if not keeping
                    if !keep_directories {
                        if let Err(e) = fs::remove_dir_all(&dir_path) {
                            eprintln!(
                                "Warning: Failed to remove directory {}: {}",
                                dir_path.display(),
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    pb.set_prefix(format!("❌ {dir_name}"));
                    pb.set_message(format!("Failed: {e}"));
                    pb.finish();

                    // Update failure stats
                    let mut stats = processor.stats.lock().await;
                    stats.failed_directories += 1;
                }
            }

            main_pb.inc(1);
        });

        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await?;
    }

    main_pb.finish_with_message("All directories processed");
    println!();

    // Calculate total time and update stats
    let end_time = std::time::Instant::now();
    let total_time = end_time.duration_since(start_time);

    // Get final wallet balance for accurate cost calculation
    let final_balance = match get_wallet_balance(&client, &config, &token.lock().await).await {
        Ok(balance) => {
            println!("{} Final wallet balance: {:.6} ETH", "💰".bold(), balance);
            Some(balance)
        }
        Err(e) => {
            eprintln!(
                "{} Warning: Could not get final wallet balance: {}",
                "⚠️".yellow(),
                e
            );
            None
        }
    };

    // Get final stats and update with timing and accurate costs
    let mut stats = processor.stats.lock().await.clone();
    stats.total_time = total_time;
    stats.initial_eth_balance = initial_balance;
    stats.final_eth_balance = final_balance;

    // Calculate accurate ETH cost from balance difference
    if let (Some(initial), Some(final_bal)) = (initial_balance, final_balance) {
        stats.total_cost_eth = initial - final_bal;
    }

    // Upload metadata to Autonomi if we had any successes
    if stats.successful_directories > 0 {
        println!(
            "{} {}",
            "📤".bold(),
            "Uploading metadata to Autonomi...".yellow()
        );

        match upload_metadata_to_autonomi(&client, &config, &token).await {
            Ok(()) => {
                println!(
                    "{} {}",
                    "✅".green(),
                    "Metadata uploaded to Autonomi successfully".green()
                );
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to upload metadata to Autonomi: {}",
                    "❌".red(),
                    e
                );
            }
        }
    }

    // Display final statistics
    display_final_stats(&stats);

    Ok(())
}

async fn refresh_token(client: &Client, config: &Config, password: &str) -> anyhow::Result<String> {
    authenticate_with_colonyd(client, config, password).await
}

async fn upload_metadata_to_autonomi(
    client: &Client,
    config: &Config,
    token: &Arc<Mutex<String>>,
) -> anyhow::Result<()> {
    let token_guard = token.lock().await;
    let upload_url = format!("{}/colony-0/jobs/cache/upload", config.base_url);

    // Start the upload job
    let response = client
        .post(&upload_url)
        .header("Authorization", format!("Bearer {}", *token_guard))
        .header("Content-Type", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(anyhow::anyhow!(
            "Upload job failed {}: {}",
            status,
            error_text
        ));
    }

    let job_response: JobResponse = response.json().await?;

    // Wait for the job to complete
    wait_for_upload_job_completion(client, config, &token_guard, &job_response.job_id).await?;

    Ok(())
}

async fn wait_for_upload_job_completion(
    client: &Client,
    config: &Config,
    token: &str,
    job_id: &str,
) -> anyhow::Result<()> {
    loop {
        let response = client
            .get(format!("{}/colony-0/jobs/{}", config.base_url, job_id))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to get job status: {}",
                response.status()
            ));
        }

        let job_status: JobStatusResponse = response.json().await?;

        match job_status.job.status.as_str() {
            "completed" => {
                return Ok(());
            }
            "failed" => {
                let error_msg = job_status
                    .job
                    .error
                    .unwrap_or_else(|| "Unknown error".to_string());
                return Err(anyhow::anyhow!("Upload job failed: {}", error_msg));
            }
            "running" | "pending" => {
                // Continue polling
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown job status: {}",
                    job_status.job.status
                ));
            }
        }
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    let millis = duration.subsec_millis();

    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else if seconds > 0 {
        format!("{seconds}.{millis:03}s")
    } else {
        format!("{millis}ms")
    }
}

fn display_final_stats(stats: &UploadStats) {
    println!();
    println!("{} {}", "📊".bold(), "Upload Summary:".bold().cyan());
    println!(
        "   {} Files uploaded: {}",
        "📁".bold(),
        stats.files_uploaded.to_string().green()
    );
    println!(
        "   {} Total size: {:.2} MB ({} bytes)",
        "💾".bold(),
        stats.total_size as f64 / 1_048_576.0,
        stats.total_size.to_string().yellow()
    );
    println!(
        "   {} Successful directories: {}",
        "✅".bold(),
        stats.successful_directories.to_string().green()
    );

    if stats.failed_directories > 0 {
        println!(
            "   {} Failed directories: {}",
            "❌".bold(),
            stats.failed_directories.to_string().red()
        );
    }

    // TODO: Add actual cost reporting when Autonomi API is integrated
    if stats.total_cost_ant > 0.0 {
        println!(
            "   {} Total cost (ANT): {:.6}",
            "💰".bold(),
            stats.total_cost_ant.to_string().yellow()
        );
    }
    if stats.total_cost_eth > 0.0 {
        println!(
            "   {} Total cost (ETH): {:.6}",
            "⛽".bold(),
            stats.total_cost_eth.to_string().yellow()
        );
    }

    // Display total time
    println!(
        "   {} Total time: {}",
        "⏱️".bold(),
        format_duration(stats.total_time).cyan()
    );

    println!();
    if stats.failed_directories == 0 {
        println!(
            "{} {}",
            "🎉".bold(),
            "All uploads completed successfully!".bold().green()
        );
    } else {
        println!(
            "{} Upload completed with {} failures",
            "⚠️".yellow(),
            stats.failed_directories.to_string().red()
        );
    }
}

async fn get_wallet_balance(client: &Client, config: &Config, token: &str) -> anyhow::Result<f64> {
    let response = client
        .get(format!("{}/colony-0/wallet/balance", config.base_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to get wallet balance: {}",
            response.status()
        ));
    }

    let balance_response: serde_json::Value = response.json().await?;
    let balance = balance_response
        .get("balance")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| anyhow::anyhow!("No balance in response"))?;

    Ok(balance)
}

async fn authenticate_with_colonyd(
    client: &Client,
    config: &Config,
    password: &str,
) -> anyhow::Result<String> {
    let auth_url = format!("{}/colony-auth/token", config.base_url);

    let auth_payload = json!({
        "password": password
    });

    let response = client.post(&auth_url).json(&auth_payload).send().await?;

    if !response.status().is_success() {
        if response.status() == 401 {
            return Err(anyhow::anyhow!("Invalid password"));
        } else if response.status().as_u16() >= 500 {
            return Err(anyhow::anyhow!(
                "Colonyd server error - is colonyd running?"
            ));
        } else {
            return Err(anyhow::anyhow!(
                "Authentication failed: {}",
                response.status()
            ));
        }
    }

    let token_response: TokenResponse = response.json().await?;
    Ok(token_response.token)
}
