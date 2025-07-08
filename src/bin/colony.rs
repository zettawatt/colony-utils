use clap::{Arg, ArgMatches, Command};
use colored::*;
use dialoguer::Password;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredToken {
    token: String,
    expires_at: u64,
    token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobResponse {
    job_id: String,
    status: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobStatus {
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
struct JobResult {
    job_id: String,
    status: String,
    result: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PodResponse {
    address: String,
    name: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreatePodRequest {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PodRefRequest {
    pod_ref: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenamePodRequest {
    name: String,
}

struct Config {
    server: String,
    port: u16,
    no_color: bool,
}

impl Config {
    fn new(matches: &ArgMatches) -> Self {
        let server = matches
            .get_one::<String>("server")
            .cloned()
            .or_else(|| env::var("COLONYCLI_SERVER").ok())
            .unwrap_or_else(|| "http://localhost".to_string());

        let port = matches
            .get_one::<String>("port")
            .and_then(|p| p.parse().ok())
            .or_else(|| env::var("COLONYCLI_PORT").ok().and_then(|p| p.parse().ok()))
            .unwrap_or(3000);

        let no_color = matches.get_flag("no-color");

        Self {
            server,
            port,
            no_color,
        }
    }

    fn base_url(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

fn get_token_cache_path() -> anyhow::Result<PathBuf> {
    let mut path =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    path.push(".colony-cli");

    // Create directory if it doesn't exist
    if !path.exists() {
        fs::create_dir_all(&path)?;
    }

    path.push("token.json");
    Ok(path)
}

fn load_cached_token() -> anyhow::Result<Option<StoredToken>> {
    let token_path = get_token_cache_path()?;

    if !token_path.exists() {
        return Ok(None);
    }

    let token_data = fs::read_to_string(token_path)?;
    let stored_token: StoredToken = serde_json::from_str(&token_data)?;

    // Check if token is expired
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    if stored_token.expires_at <= now {
        return Ok(None); // Token is expired
    }

    Ok(Some(stored_token))
}

fn save_token_to_cache(token: &str, expires_in: u64, token_type: &str) -> anyhow::Result<()> {
    let token_path = get_token_cache_path()?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let stored_token = StoredToken {
        token: token.to_string(),
        expires_at: now + expires_in,
        token_type: token_type.to_string(),
    };

    let token_data = serde_json::to_string_pretty(&stored_token)?;
    fs::write(token_path, token_data)?;

    Ok(())
}

async fn request_new_token(config: &Config) -> anyhow::Result<String> {
    println!("{}", "🔐 Authentication required".yellow());

    let password = Password::new()
        .with_prompt("Enter keystore password")
        .interact()?;

    let client = Client::new();
    let url = format!("{}/colony-auth/token", config.base_url());

    let auth_request = AuthRequest { password };

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&auth_request)
        .send()
        .await?;

    if response.status().is_success() {
        let token_response: TokenResponse = response.json().await?;

        // Save token to cache
        save_token_to_cache(
            &token_response.token,
            token_response.expires_in,
            &token_response.token_type,
        )?;

        println!("{}", "✅ Authentication successful".green());
        Ok(token_response.token)
    } else {
        let error_text = response.text().await?;
        anyhow::bail!("Failed to authenticate: {}", error_text);
    }
}

async fn get_jwt_token(config: &Config) -> anyhow::Result<String> {
    // Try to load cached token first
    if let Ok(Some(stored_token)) = load_cached_token() {
        return Ok(stored_token.token);
    }

    // If no valid cached token, request a new one
    request_new_token(config).await
}

async fn wait_for_job_completion(
    config: &Config,
    token: &str,
    job_id: &str,
    operation_name: &str,
) -> anyhow::Result<Value> {
    let client = Client::new();
    let base_url = config.base_url();

    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(format!("🔄 {operation_name}"));

    loop {
        // Check job status
        let status_url = format!("{base_url}/colony-0/jobs/{job_id}");
        let response = client
            .get(&status_url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;

        if response.status().is_success() {
            let job_status: JobStatus = response.json().await?;
            let job = job_status.job;

            // Update progress bar message
            if let Some(message) = &job.message {
                pb.set_message(format!("🔄 {operation_name} - {message}"));
            }

            match job.status.as_str() {
                "completed" => {
                    pb.finish_with_message(format!("✅ {operation_name} completed"));

                    // Get the result
                    let result_url = format!("{base_url}/colony-0/jobs/{job_id}/result");
                    let result_response = client
                        .get(&result_url)
                        .header("Authorization", format!("Bearer {token}"))
                        .send()
                        .await?;

                    if result_response.status().is_success() {
                        let job_result: JobResult = result_response.json().await?;
                        return Ok(job_result.result.unwrap_or(json!({})));
                    } else {
                        let error_text = result_response.text().await?;
                        anyhow::bail!("Failed to get job result: {}", error_text);
                    }
                }
                "failed" => {
                    pb.finish_with_message(format!("❌ {operation_name} failed"));
                    let error_msg = job.error.unwrap_or_else(|| "Unknown error".to_string());
                    anyhow::bail!("Job failed: {}", error_msg);
                }
                _ => {
                    // Job is still running, continue polling
                    pb.tick();
                    sleep(Duration::from_millis(500)).await;
                }
            }
        } else {
            pb.finish_with_message(format!("❌ Failed to check {operation_name} status"));
            let error_text = response.text().await?;
            anyhow::bail!("Failed to check job status: {}", error_text);
        }
    }
}

async fn wait_for_job_completion_no_auth(
    config: &Config,
    job_id: &str,
    operation_name: &str,
) -> anyhow::Result<Value> {
    let client = Client::new();
    let base_url = config.base_url();

    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(format!("🔄 {operation_name}"));

    loop {
        // Check job status (no auth required for public job endpoints)
        let status_url = format!("{base_url}/colony-0/jobs/{job_id}");
        let response = client.get(&status_url).send().await?;

        if response.status().is_success() {
            let job_status: JobStatus = response.json().await?;
            let job = job_status.job;

            // Update progress bar message
            if let Some(message) = &job.message {
                pb.set_message(format!("🔄 {operation_name} - {message}"));
            }

            match job.status.as_str() {
                "completed" => {
                    pb.finish_with_message(format!("✅ {operation_name} completed"));

                    // Get the result (no auth required for public job endpoints)
                    let result_url = format!("{base_url}/colony-0/jobs/{job_id}/result");
                    let result_response = client.get(&result_url).send().await?;

                    if result_response.status().is_success() {
                        let job_result: JobResult = result_response.json().await?;
                        return Ok(job_result.result.unwrap_or(json!({})));
                    } else {
                        let error_text = result_response.text().await?;
                        anyhow::bail!("Failed to get job result: {}", error_text);
                    }
                }
                "failed" => {
                    pb.finish_with_message(format!("❌ {operation_name} failed"));
                    let error_msg = job.error.unwrap_or_else(|| "Unknown error".to_string());
                    anyhow::bail!("Job failed: {}", error_msg);
                }
                _ => {
                    // Job is still running, continue polling
                    pb.tick();
                    sleep(Duration::from_millis(500)).await;
                }
            }
        } else {
            pb.finish_with_message(format!("❌ Failed to check {operation_name} status"));
            let error_text = response.text().await?;
            anyhow::bail!("Failed to check job status: {}", error_text);
        }
    }
}

fn print_json_pretty(value: &Value) {
    if let Ok(pretty) = serde_json::to_string_pretty(value) {
        println!("{pretty}");
    } else {
        println!("{value}");
    }
}

fn print_search_results_table(value: &Value) {
    // Check if this is a search response with SPARQL results
    let bindings_array = if let Some(sparql_results) = value.get("sparql_results") {
        // New format: sparql_results.results.bindings
        if let Some(results) = sparql_results.get("results") {
            if let Some(bindings) = results.get("bindings") {
                bindings.as_array()
            } else {
                None
            }
        } else {
            None
        }
    } else if let Some(results) = value.get("results") {
        // Direct format: results.bindings
        if let Some(bindings) = results.get("bindings") {
            bindings.as_array()
        } else {
            None
        }
    } else {
        None
    };

    if let Some(bindings_array) = bindings_array {
        if bindings_array.is_empty() {
            println!("{}", "No results found.".yellow());
            return;
        }

        // Check if this is a subject search by looking at the SPARQL variable structure
        // Subject searches use 'graph', 'predicate', 'object' variables
        // General searches use 'subject', 'predicate', 'object' variables
        let has_graph_vars = bindings_array.iter().any(|binding| {
            binding.get("graph").is_some()
                && binding.get("predicate").is_some()
                && binding.get("object").is_some()
        });

        let has_subject_vars = bindings_array
            .iter()
            .any(|binding| binding.get("subject").is_some());

        // Check if this is a browse search by looking for 'name', 'type', and 'description' variables
        let has_browse_vars = bindings_array
            .iter()
            .any(|binding| binding.get("name").is_some() && binding.get("type").is_some());

        if has_graph_vars && !has_subject_vars {
            // This is a subject search - display detailed information
            print_subject_details(value, bindings_array);
        } else if has_browse_vars {
            // This is a browse search - display browse table format
            print_browse_results_table(bindings_array);
        } else {
            // This is a general search - display table format
            print_subjects_table(bindings_array);
        }
        return;
    }

    // Fallback to pretty JSON if not SPARQL format
    print_json_pretty(value);
}

fn print_subject_details(value: &Value, bindings_array: &[Value]) {
    // For subject searches, collect unique pods from 'graph' field and predicate-object pairs from 'predicate' and 'object' fields
    let mut unique_pods = std::collections::HashSet::new();
    let mut predicate_objects = Vec::new();

    for binding in bindings_array {
        // Extract pod address from 'graph' field
        if let Some(graph_obj) = binding.get("graph") {
            if let Some(graph_value) = graph_obj.get("value") {
                if let Some(graph_str) = graph_value.as_str() {
                    unique_pods.insert(graph_str.to_string());
                }
            }
        }

        // Extract predicate-object pairs from 'predicate' and 'object' fields
        if let (Some(predicate_obj), Some(object_obj)) =
            (binding.get("predicate"), binding.get("object"))
        {
            if let (Some(predicate_str), Some(object_str)) = (
                predicate_obj.get("value").and_then(|v| v.as_str()),
                object_obj.get("value").and_then(|v| v.as_str()),
            ) {
                predicate_objects.push((predicate_str.to_string(), object_str.to_string()));
            }
        }
    }

    // Display pods found
    if !unique_pods.is_empty() {
        println!("{}", "📦 Found in pods:".cyan().bold());
        for pod in &unique_pods {
            let pod_display = if pod.starts_with("ant://") {
                pod.strip_prefix("ant://").unwrap_or(pod)
            } else {
                pod
            };
            println!("  {}", pod_display.blue());
        }
        println!();
    }

    // Also check for pods_found in the response (fallback)
    if let Some(pods_found) = value.get("pods_found") {
        if let Some(pods_array) = pods_found.as_array() {
            if !pods_array.is_empty() && unique_pods.is_empty() {
                println!("{}", "📦 Found in pods:".cyan().bold());
                for pod in pods_array {
                    if let Some(pod_str) = pod.as_str() {
                        let pod_display = if pod_str.starts_with("ant://") {
                            pod_str.strip_prefix("ant://").unwrap_or(pod_str)
                        } else {
                            pod_str
                        };
                        println!("  {}", pod_display.blue());
                    }
                }
                println!();
            }
        }
    }

    if !predicate_objects.is_empty() {
        println!("{}", "📋 Properties:".cyan().bold());
        println!(
            "{}",
            format!("{:<50} {}", "Predicate", "Object").cyan().bold()
        );
        println!("{}", "─".repeat(172).cyan());

        for (predicate, object) in predicate_objects {
            // Strip schema.org and colonylib prefixes
            let predicate_clean = predicate
                .strip_prefix("http://schema.org/")
                .unwrap_or(&predicate)
                .strip_prefix("https://schema.org/")
                .unwrap_or(&predicate)
                .strip_prefix("ant://colonylib/vocabulary/0.1/predicate#")
                .unwrap_or(&predicate);

            // Truncate predicate if too long
            let predicate_display = if predicate_clean.len() > 48 {
                format!("{}...", &predicate_clean[..45])
            } else {
                predicate_clean.to_string()
            };

            // Word wrap object text to 120 characters
            let wrapped_lines = wrap_text(&object, 120);

            // Print first line with predicate
            if let Some(first_line) = wrapped_lines.first() {
                println!("{:<50} {}", predicate_display.green(), first_line.white());
            }

            // Print remaining lines with padding
            for line in wrapped_lines.iter().skip(1) {
                println!("{:<50} {}", "", line.white());
            }
        }
    }
}

fn print_subjects_table(bindings_array: &[Value]) {
    // Group bindings by subject to collect name and description for each subject
    let mut subjects = std::collections::HashMap::new();

    for binding in bindings_array {
        // Extract subject address
        let subject_address = if let Some(subject_obj) = binding.get("subject") {
            if let Some(subject_value) = subject_obj.get("value") {
                if let Some(subject_str) = subject_value.as_str() {
                    // Extract the address part from ant:// URIs
                    if subject_str.starts_with("ant://") {
                        subject_str
                            .strip_prefix("ant://")
                            .unwrap_or(subject_str)
                            .to_string()
                    } else {
                        subject_str.to_string()
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        };

        // Get or create subject entry
        let subject_entry = subjects
            .entry(subject_address.clone())
            .or_insert_with(|| (String::new(), String::new(), subject_address));

        // Extract predicate and object
        if let Some(predicate_obj) = binding.get("predicate") {
            if let Some(predicate_value) = predicate_obj.get("value") {
                if let Some(predicate_str) = predicate_value.as_str() {
                    if let Some(object_obj) = binding.get("object") {
                        if let Some(object_value) = object_obj.get("value") {
                            if let Some(object_str) = object_value.as_str() {
                                match predicate_str {
                                    "http://schema.org/name" => {
                                        subject_entry.0 = object_str.to_string();
                                    }
                                    "ant://colonylib/vocabulary/0.1/predicate#name" => {
                                        subject_entry.0 = object_str.to_string();
                                    }
                                    "http://schema.org/description" => {
                                        subject_entry.1 = object_str.to_string();
                                    }
                                    "ant://colonylib/vocabulary/0.1/predicate#addr_type" => {
                                        match object_str {
                                            "ant://colonylib/vocabulary/0.1/object#pod" => {
                                                subject_entry.1 = "Pod".to_string();
                                            }
                                            "ant://colonylib/vocabulary/0.1/object#pod_ref" => {
                                                subject_entry.1 = "Pod Reference".to_string();
                                            }
                                            _ => {}
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if subjects.is_empty() {
        println!("{}", "No results found.".yellow());
        return;
    }

    // Print table header
    println!(
        "{}",
        format!("{:<30} {:<50} {:<96}", "Name", "Description", "Address")
            .cyan()
            .bold()
    );
    println!("{}", "─".repeat(178).cyan());

    // Print each subject
    for (name, description, address) in subjects.values() {
        // Truncate long values for table display
        let name_display = if name.len() > 28 {
            format!("{}...", &name[..25])
        } else {
            name.clone()
        };
        let desc_display = if description.len() > 48 {
            format!("{}...", &description[..45])
        } else {
            description.clone()
        };
        let addr_display = if address.len() > 96 {
            format!("{}...", &address[..93])
        } else {
            address.clone()
        };

        println!(
            "{:<30} {:<50} {:<96}",
            name_display.green(),
            desc_display.white(),
            addr_display.blue()
        );
    }
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn print_browse_results_table(bindings_array: &[Value]) {
    if bindings_array.is_empty() {
        println!("{}", "No results found.".yellow());
        return;
    }

    // Print table header
    println!(
        "{}",
        format!("{:<30} {:<50} {:<96}", "Name", "Description", "Address")
            .cyan()
            .bold()
    );
    println!("{}", "─".repeat(178).cyan());

    // Process each binding
    for binding in bindings_array {
        // Extract name
        let name = if let Some(name_obj) = binding.get("name") {
            if let Some(name_value) = name_obj.get("value") {
                name_value.as_str().unwrap_or("").to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Extract description
        let description = if let Some(desc_obj) = binding.get("description") {
            if let Some(desc_value) = desc_obj.get("value") {
                desc_value.as_str().unwrap_or("").to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Extract subject address (the actual resource address)
        let address = if let Some(subject_obj) = binding.get("subject") {
            if let Some(subject_value) = subject_obj.get("value") {
                if let Some(subject_str) = subject_value.as_str() {
                    // Extract the address part from ant:// URIs
                    if subject_str.starts_with("ant://") {
                        subject_str
                            .strip_prefix("ant://")
                            .unwrap_or(subject_str)
                            .to_string()
                    } else {
                        subject_str.to_string()
                    }
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Truncate long values for table display
        let name_display = if name.len() > 28 {
            format!("{}...", &name[..25])
        } else {
            name
        };
        let desc_display = if description.len() > 48 {
            format!("{}...", &description[..45])
        } else {
            description
        };
        let addr_display = if address.len() > 96 {
            format!("{}...", &address[..93])
        } else {
            address
        };

        println!(
            "{:<30} {:<50} {:<96}",
            name_display.green(),
            desc_display.white(),
            addr_display.blue()
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Command::new("colony")
        .version("0.2.5")
        .author("Chuck McClish")
        .about("A colonylib CLI for interacting with the colonyd daemon")
        .arg(
            Arg::new("server")
                .short('s')
                .long("server")
                .value_name("SERVER")
                .help("Server to connect to (default http://localhost or COLONYCLI_SERVER env var)")
                .global(true),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to connect to the daemon on (default 3000 or COLONYCLI_PORT env var)")
                .global(true),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable color output")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .subcommand(
            Command::new("refresh")
                .about("🔄 Refresh cache or pod references")
                .arg(
                    Arg::new("depth")
                        .long("depth")
                        .value_name("DEPTH")
                        .help("Depth for refreshing pod references"),
                ),
        )
        .subcommand(
            Command::new("upload")
                .about("⬆️ Upload cache or specific pod")
                .arg(
                    Arg::new("pod")
                        .value_name("POD")
                        .help("Specific pod to upload"),
                ),
        )
        .subcommand(
            Command::new("search")
                .about("🔍 Search operations")
                .subcommand(
                    Command::new("sparql")
                        .about("Search using SPARQL query")
                        .arg(
                            Arg::new("query")
                                .value_name("QUERY")
                                .help("SPARQL query to execute")
                                .required(true),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Display raw JSON output instead of formatted table")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("browse")
                        .about("Browse the network")
                        .arg(
                            Arg::new("limit")
                                .long("limit")
                                .value_name("LIMIT")
                                .help("Maximum number of results (default: 50)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Display raw JSON output instead of formatted table")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("text")
                        .about("Search by text")
                        .arg(
                            Arg::new("query")
                                .value_name("QUERY")
                                .help("Text to search for")
                                .required(true),
                        )
                        .arg(
                            Arg::new("limit")
                                .long("limit")
                                .value_name("LIMIT")
                                .help("Maximum number of results (default: 50)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Display raw JSON output instead of formatted table")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("type")
                        .about("Search by type")
                        .arg(
                            Arg::new("type")
                                .value_name("TYPE")
                                .help("Type name to search for")
                                .required(true),
                        )
                        .arg(
                            Arg::new("limit")
                                .long("limit")
                                .value_name("LIMIT")
                                .help("Maximum number of results (default: 50)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Display raw JSON output instead of formatted table")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("predicate")
                        .about("Search by predicate")
                        .arg(
                            Arg::new("predicate")
                                .value_name("PREDICATE")
                                .help("Predicate name to search for")
                                .required(true),
                        )
                        .arg(
                            Arg::new("limit")
                                .long("limit")
                                .value_name("LIMIT")
                                .help("Maximum number of results (default: 50)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Display raw JSON output instead of formatted table")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("subject")
                        .about("Search by subject")
                        .arg(
                            Arg::new("subject")
                                .value_name("SUBJECT")
                                .help("Subject to search for")
                                .required(true),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Display raw JSON output instead of formatted table")
                                .action(clap::ArgAction::SetTrue),
                        ),
                ),
        )
        .subcommand(
            Command::new("pods").about("📦 List all pods").arg(
                Arg::new("json")
                    .long("json")
                    .help("Display raw JSON output instead of formatted table")
                    .action(clap::ArgAction::SetTrue),
            ),
        )
        .subcommand(
            Command::new("add")
                .about("➕ Add operations")
                .subcommand(
                    Command::new("pod").about("Add a new pod").arg(
                        Arg::new("name")
                            .value_name("NAME")
                            .help("Name for the new pod")
                            .required(true),
                    ),
                )
                .subcommand(
                    Command::new("ref")
                        .about("Add a pod reference")
                        .arg(
                            Arg::new("pod")
                                .value_name("POD")
                                .help("Pod address")
                                .required(true),
                        )
                        .arg(
                            Arg::new("ref")
                                .value_name("REF")
                                .help("Reference to add")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            Command::new("rm")
                .about("🗑️ Remove operations")
                .subcommand(
                    Command::new("pod").about("Remove a pod").arg(
                        Arg::new("address")
                            .value_name("POD_ADDRESS")
                            .help("Pod address to remove")
                            .required(true),
                    ),
                )
                .subcommand(
                    Command::new("ref")
                        .about("Remove a pod reference")
                        .arg(
                            Arg::new("pod")
                                .value_name("POD")
                                .help("Pod address")
                                .required(true),
                        )
                        .arg(
                            Arg::new("ref")
                                .value_name("REF")
                                .help("Reference to remove")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            Command::new("rename")
                .about("✏️ Rename operations")
                .subcommand(
                    Command::new("pod")
                        .about("Rename a pod")
                        .arg(
                            Arg::new("address")
                                .value_name("POD_ADDRESS")
                                .help("Pod address to rename")
                                .required(true),
                        )
                        .arg(
                            Arg::new("name")
                                .value_name("NEW_NAME")
                                .help("New name for the pod")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            Command::new("put")
                .about("📝 Put subject data")
                .arg(
                    Arg::new("pod")
                        .value_name("POD")
                        .help("Pod address")
                        .required(true),
                )
                .arg(
                    Arg::new("subject")
                        .value_name("SUBJECT")
                        .help("Subject identifier")
                        .required(true),
                )
                .arg(
                    Arg::new("data")
                        .value_name("DATA")
                        .help("JSON data to store")
                        .required(true),
                ),
        );

    let matches = app.get_matches();
    let config = Config::new(&matches);

    // Initialize colored output
    if config.no_color {
        colored::control::set_override(false);
    }

    match matches.subcommand() {
        Some(("refresh", sub_matches)) => {
            handle_refresh(&config, sub_matches).await?;
        }
        Some(("upload", sub_matches)) => {
            handle_upload(&config, sub_matches).await?;
        }
        Some(("search", sub_matches)) => {
            handle_search(&config, sub_matches).await?;
        }
        Some(("pods", sub_matches)) => {
            handle_pods(&config, sub_matches).await?;
        }
        Some(("add", sub_matches)) => {
            handle_add(&config, sub_matches).await?;
        }
        Some(("rm", sub_matches)) => {
            handle_rm(&config, sub_matches).await?;
        }
        Some(("rename", sub_matches)) => {
            handle_rename(&config, sub_matches).await?;
        }
        Some(("put", sub_matches)) => {
            handle_put(&config, sub_matches).await?;
        }
        _ => {
            println!(
                "{}",
                "❌ No command specified. Use --help for usage information.".red()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

// Handler functions
async fn handle_refresh(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    println!("{}", "🔄 Starting cache refresh...".cyan());

    let client = Client::new();
    let base_url = config.base_url();

    let (url, operation_name) = if let Some(depth) = matches.get_one::<String>("depth") {
        (
            format!("{base_url}/colony-0/jobs/cache/refresh/{depth}"),
            format!("Cache refresh with depth {depth}"),
        )
    } else {
        (
            format!("{base_url}/colony-0/jobs/cache/refresh"),
            "Cache refresh".to_string(),
        )
    };

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .send()
        .await?;

    if response.status().is_success() {
        let job_response: JobResponse = response.json().await?;
        let result =
            wait_for_job_completion_no_auth(config, &job_response.job_id, &operation_name).await?;

        println!("\n{}", "📋 Result:".green().bold());
        print_json_pretty(&result);
    } else {
        let error_text = response.text().await?;
        println!("{} {}", "❌ Failed to start refresh:".red(), error_text);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_upload(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    let token = get_jwt_token(config).await?;
    let client = Client::new();
    let base_url = config.base_url();

    let (url, operation_name) = if let Some(pod) = matches.get_one::<String>("pod") {
        println!("{} {}", "⬆️ Starting upload for pod:".cyan(), pod.yellow());
        (
            format!("{base_url}/colony-0/jobs/cache/upload/{pod}"),
            format!("Upload pod {pod}"),
        )
    } else {
        println!("{}", "⬆️ Starting upload all...".cyan());
        (
            format!("{base_url}/colony-0/jobs/cache/upload"),
            "Upload all".to_string(),
        )
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send()
        .await?;

    if response.status().is_success() {
        let job_response: JobResponse = response.json().await?;
        let result =
            wait_for_job_completion(config, &token, &job_response.job_id, &operation_name).await?;

        println!("\n{}", "📋 Result:".green().bold());
        print_json_pretty(&result);
    } else {
        let error_text = response.text().await?;
        println!("{} {}", "❌ Failed to start upload:".red(), error_text);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_search(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    let client = Client::new();
    let base_url = config.base_url();

    match matches.subcommand() {
        Some(("sparql", sub_matches)) => {
            let query = sub_matches.get_one::<String>("query").unwrap();
            let json = sub_matches.get_flag("json");
            println!("{} {}", "🔍 Executing SPARQL query:".cyan(), query.yellow());

            let search_payload = json!({
                "type": "advanced",
                "sparql": query
            });

            // Use asynchronous job-based search endpoint (public)
            let response = client
                .post(format!("{base_url}/colony-0/jobs/search"))
                .header("Content-Type", "application/json")
                .json(&search_payload)
                .send()
                .await?;

            if response.status().is_success() {
                let job_response: JobResponse = response.json().await?;
                let result =
                    wait_for_job_completion_no_auth(config, &job_response.job_id, "SPARQL search")
                        .await?;

                println!("\n{}", "📋 Search Results:".green().bold());
                if json {
                    print_json_pretty(&result);
                } else {
                    print_search_results_table(&result);
                }
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to start search:".red(), error_text);
                std::process::exit(1);
            }
        }
        Some(("text", sub_matches)) => {
            let query = sub_matches.get_one::<String>("query").unwrap();
            let json = sub_matches.get_flag("json");
            let limit: u32 = sub_matches
                .get_one::<String>("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(50);

            println!(
                "{} {} (limit: {})",
                "🔍 Searching text:".cyan(),
                query.yellow(),
                limit
            );

            let search_payload = json!({
                "type": "text",
                "text": query,
                "limit": limit
            });

            // Use asynchronous job-based search endpoint (public)
            let response = client
                .post(format!("{base_url}/colony-0/jobs/search"))
                .header("Content-Type", "application/json")
                .json(&search_payload)
                .send()
                .await?;

            if response.status().is_success() {
                let job_response: JobResponse = response.json().await?;
                let result =
                    wait_for_job_completion_no_auth(config, &job_response.job_id, "Text search")
                        .await?;

                println!("\n{}", "📋 Search Results:".green().bold());
                if json {
                    print_json_pretty(&result);
                } else {
                    print_search_results_table(&result);
                }
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to start search:".red(), error_text);
                std::process::exit(1);
            }
        }
        Some(("browse", sub_matches)) => {
            let json = sub_matches.get_flag("json");
            let limit: u32 = sub_matches
                .get_one::<String>("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(50);

            println!("{} (limit: {})", "🔍 Browsing:".cyan(), limit);

            let search_payload = json!({
                "type": "browse",
                "limit": limit
            });

            // Use asynchronous job-based search endpoint (public)
            let response = client
                .post(format!("{base_url}/colony-0/jobs/search"))
                .header("Content-Type", "application/json")
                .json(&search_payload)
                .send()
                .await?;

            if response.status().is_success() {
                let job_response: JobResponse = response.json().await?;
                let result =
                    wait_for_job_completion_no_auth(config, &job_response.job_id, "Browse search")
                        .await?;

                println!("\n{}", "📋 Search Results:".green().bold());
                if json {
                    print_json_pretty(&result);
                } else {
                    print_search_results_table(&result);
                }
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to start search:".red(), error_text);
                std::process::exit(1);
            }
        }
        Some(("type", sub_matches)) => {
            let type_name = sub_matches.get_one::<String>("type").unwrap();
            let json = sub_matches.get_flag("json");
            let limit: u32 = sub_matches
                .get_one::<String>("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(50);

            println!(
                "{} {} (limit: {})",
                "🔍 Searching by type:".cyan(),
                type_name.yellow(),
                limit
            );

            let search_payload = json!({
                "type": "by-type",
                "by_type": type_name,
                "limit": limit
            });

            // Use asynchronous job-based search endpoint (public)
            let response = client
                .post(format!("{base_url}/colony-0/jobs/search"))
                .header("Content-Type", "application/json")
                .json(&search_payload)
                .send()
                .await?;

            if response.status().is_success() {
                let job_response: JobResponse = response.json().await?;
                let result =
                    wait_for_job_completion_no_auth(config, &job_response.job_id, "Type search")
                        .await?;

                println!("\n{}", "📋 Search Results:".green().bold());
                if json {
                    print_json_pretty(&result);
                } else {
                    print_search_results_table(&result);
                }
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to start search:".red(), error_text);
                std::process::exit(1);
            }
        }
        Some(("predicate", sub_matches)) => {
            let predicate = sub_matches.get_one::<String>("predicate").unwrap();
            let json = sub_matches.get_flag("json");
            let limit: u32 = sub_matches
                .get_one::<String>("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(50);

            println!(
                "{} {} (limit: {})",
                "🔍 Searching by predicate:".cyan(),
                predicate.yellow(),
                limit
            );

            let search_payload = json!({
                "type": "by-predicate",
                "by_predicate": predicate,
                "limit": limit
            });

            // Use asynchronous job-based search endpoint (public)
            let response = client
                .post(format!("{base_url}/colony-0/jobs/search"))
                .header("Content-Type", "application/json")
                .json(&search_payload)
                .send()
                .await?;

            if response.status().is_success() {
                let job_response: JobResponse = response.json().await?;
                let result = wait_for_job_completion_no_auth(
                    config,
                    &job_response.job_id,
                    "Predicate search",
                )
                .await?;

                println!("\n{}", "📋 Search Results:".green().bold());
                if json {
                    print_json_pretty(&result);
                } else {
                    print_search_results_table(&result);
                }
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to start search:".red(), error_text);
                std::process::exit(1);
            }
        }
        Some(("subject", sub_matches)) => {
            let subject = sub_matches.get_one::<String>("subject").unwrap();
            let json = sub_matches.get_flag("json");
            println!("{} {}", "🔍 Searching by subject:".cyan(), subject.yellow());

            // Use asynchronous job-based search endpoint (public)
            let response = client
                .post(format!("{base_url}/colony-0/jobs/search/subject/{subject}"))
                .header("Content-Type", "application/json")
                .send()
                .await?;

            if response.status().is_success() {
                let job_response: JobResponse = response.json().await?;
                let result =
                    wait_for_job_completion_no_auth(config, &job_response.job_id, "Subject search")
                        .await?;

                println!("\n{}", "📋 Search Results:".green().bold());
                if json {
                    print_json_pretty(&result);
                } else {
                    print_search_results_table(&result);
                }
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to start search:".red(), error_text);
                std::process::exit(1);
            }
        }
        _ => {
            println!(
                "{}",
                "❌ No search subcommand specified. Use --help for usage information.".red()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn handle_pods(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    println!("{}", "📦 Listing pods...".cyan());

    let token = get_jwt_token(config).await?;
    let client = Client::new();
    let base_url = config.base_url();
    let json = matches.get_flag("json");

    let response = client
        .get(format!("{base_url}/colony-0/pods"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await?;

    if response.status().is_success() {
        let result: Value = response.json().await?;
        if json {
            print_json_pretty(&result);
        } else {
            println!("\n{}", "✅ Found local pod information!".green().bold());
            print_pods_table(&result);
        }
    } else {
        let error_text = response.text().await?;
        println!("{} {}", "❌ Failed to list pods:".red(), error_text);
        std::process::exit(1);
    }

    Ok(())
}

fn print_pods_table(value: &Value) {
    // Check if this is a SPARQL response format
    let bindings_array = if let Some(results) = value.get("results") {
        if let Some(bindings) = results.get("bindings") {
            bindings.as_array()
        } else {
            None
        }
    } else {
        None
    };

    if let Some(bindings_array) = bindings_array {
        if bindings_array.is_empty() {
            println!("{}", "📦 No pods found".yellow());
            return;
        }

        // Group bindings by pod address to collect metadata for each pod
        let mut pods = std::collections::HashMap::new();

        for binding in bindings_array {
            // Extract pod address from 'graph' field (this represents the pod)
            let pod_address = if let Some(graph_obj) = binding.get("graph") {
                if let Some(graph_value) = graph_obj.get("value") {
                    if let Some(graph_str) = graph_value.as_str() {
                        // Extract the address part from ant:// URIs
                        if graph_str.starts_with("ant://") {
                            graph_str
                                .strip_prefix("ant://")
                                .unwrap_or(graph_str)
                                .to_string()
                        } else {
                            graph_str.to_string()
                        }
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            };

            // Extract predicate and object
            let predicate = binding
                .get("predicate")
                .and_then(|p| p.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let object = binding
                .get("object")
                .and_then(|o| o.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Initialize pod entry if not exists
            let pod_entry = pods.entry(pod_address.clone()).or_insert_with(|| {
                std::collections::HashMap::from([
                    ("address".to_string(), pod_address.clone()),
                    ("name".to_string(), "POD REFERENCE".to_string()),
                    ("modified".to_string(), "".to_string()),
                ])
            });

            // Update pod metadata based on predicate
            match predicate {
                "http://schema.org/name" => {
                    pod_entry.insert("name".to_string(), object.to_string());
                }
                "ant://colonylib/v1/modified" => {
                    pod_entry.insert("modified".to_string(), object.to_string());
                }
                _ => {} // Ignore other predicates for now
            }
        }

        if pods.is_empty() {
            println!("{}", "📦 No pods found".yellow());
            return;
        }

        println!("\n{}", "📦 Local Pods:".cyan().bold());
        println!(
            "{}",
            format!("{:<30} {:<96} {:<30}", "Pod Name", "Address", "Modified")
                .cyan()
                .bold()
        );
        println!("{}", "─".repeat(156).cyan());

        for pod_data in pods.values() {
            let unknown = "Unknown".to_string();
            let name = pod_data.get("name").unwrap_or(&unknown);
            let address = pod_data.get("address").unwrap_or(&unknown);
            let modified = pod_data.get("modified").unwrap_or(&unknown);

            // Truncate long values for table display
            let name_display = if name.len() > 28 {
                format!("{}...", &name[..25])
            } else {
                name.to_string()
            };
            let addr_display = address.to_string();
            let modified_display = if modified.len() > 28 {
                format!("{}...", &modified[..25])
            } else {
                modified.to_string()
            };

            println!(
                "{:<30} {:<96} {:<30}",
                name_display.green(),
                addr_display.blue(),
                modified_display.white()
            );
        }
    } else {
        // Fallback: display as JSON if not SPARQL format
        println!(
            "{}",
            "⚠️  Unexpected response format, displaying as JSON:".yellow()
        );
        print_json_pretty(value);
    }
}

async fn handle_add(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    let token = get_jwt_token(config).await?;
    let client = Client::new();
    let base_url = config.base_url();

    match matches.subcommand() {
        Some(("pod", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap();
            println!("{} {}", "➕ Adding new pod:".cyan(), name.yellow());

            let pod_request = CreatePodRequest { name: name.clone() };

            let response = client
                .post(format!("{base_url}/colony-0/pods"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .json(&pod_request)
                .send()
                .await?;

            if response.status().is_success() {
                let pod: PodResponse = response.json().await?;
                println!("\n{}", "✅ Pod created successfully!".green().bold());
                println!(
                    "📦 {} {} ({})",
                    "Name:".blue(),
                    pod.name.yellow().bold(),
                    pod.address.cyan()
                );
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to create pod:".red(), error_text);
                std::process::exit(1);
            }
        }
        Some(("ref", sub_matches)) => {
            let pod = sub_matches.get_one::<String>("pod").unwrap();
            let pod_ref = sub_matches.get_one::<String>("ref").unwrap();
            println!(
                "{} {} to pod {}",
                "➕ Adding reference".cyan(),
                pod_ref.yellow(),
                pod.yellow()
            );

            let ref_request = PodRefRequest {
                pod_ref: pod_ref.clone(),
            };

            let response = client
                .post(format!("{base_url}/colony-0/pods/{pod}/pod_ref"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .json(&ref_request)
                .send()
                .await?;

            if response.status().is_success() {
                //let result: Value = response.json().await?;
                println!("\n{}", "✅ Reference added successfully!".green().bold());
                //print_json_pretty(&result);
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to add reference:".red(), error_text);
                std::process::exit(1);
            }
        }
        _ => {
            println!(
                "{}",
                "❌ No add subcommand specified. Use --help for usage information.".red()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn handle_rm(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    let token = get_jwt_token(config).await?;
    let client = Client::new();
    let base_url = config.base_url();

    match matches.subcommand() {
        Some(("pod", sub_matches)) => {
            let pod_address = sub_matches.get_one::<String>("address").unwrap();
            println!("{} {}", "🗑️ Removing pod:".cyan(), pod_address.yellow());

            let response = client
                .delete(format!("{base_url}/colony-0/pods/{pod_address}"))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await?;

            if response.status().is_success() {
                println!("\n{}", "✅ Pod removed successfully!".green().bold());
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to remove pod:".red(), error_text);
                std::process::exit(1);
            }
        }
        Some(("ref", sub_matches)) => {
            let pod = sub_matches.get_one::<String>("pod").unwrap();
            let pod_ref = sub_matches.get_one::<String>("ref").unwrap();
            println!(
                "{} {} from pod {}",
                "🗑️ Removing reference".cyan(),
                pod_ref.yellow(),
                pod.yellow()
            );

            let ref_request = PodRefRequest {
                pod_ref: pod_ref.clone(),
            };

            let response = client
                .delete(format!("{base_url}/colony-0/pods/{pod}/pod_ref"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .json(&ref_request)
                .send()
                .await?;

            if response.status().is_success() {
                //let result: Value = response.json().await?;
                println!("\n{}", "✅ Reference removed successfully!".green().bold());
                //print_json_pretty(&result);
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to remove reference:".red(), error_text);
                std::process::exit(1);
            }
        }
        _ => {
            println!(
                "{}",
                "❌ No rm subcommand specified. Use --help for usage information.".red()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn handle_rename(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    let token = get_jwt_token(config).await?;
    let client = Client::new();
    let base_url = config.base_url();

    match matches.subcommand() {
        Some(("pod", sub_matches)) => {
            let pod_address = sub_matches.get_one::<String>("address").unwrap();
            let new_name = sub_matches.get_one::<String>("name").unwrap();
            println!(
                "{} {} to {}",
                "✏️ Renaming pod".cyan(),
                pod_address.yellow(),
                new_name.yellow()
            );

            let rename_request = RenamePodRequest {
                name: new_name.clone(),
            };

            let response = client
                .post(format!("{base_url}/colony-0/pods/{pod_address}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .json(&rename_request)
                .send()
                .await?;

            if response.status().is_success() {
                println!("\n{}", "✅ Pod renamed successfully!".green().bold());
            } else {
                let error_text = response.text().await?;
                println!("{} {}", "❌ Failed to rename pod:".red(), error_text);
                std::process::exit(1);
            }
        }
        _ => {
            println!(
                "{}",
                "❌ No rename subcommand specified. Use --help for usage information.".red()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn handle_put(config: &Config, matches: &ArgMatches) -> anyhow::Result<()> {
    let pod = matches.get_one::<String>("pod").unwrap();
    let subject = matches.get_one::<String>("subject").unwrap();
    let data_str = matches.get_one::<String>("data").unwrap();

    println!(
        "{} {} in pod {} for subject {}",
        "📝 Putting data".cyan(),
        data_str.yellow(),
        pod.yellow(),
        subject.yellow()
    );

    // Parse the JSON data
    let data: Value = match serde_json::from_str(data_str) {
        Ok(json) => json,
        Err(err) => {
            println!("{} Invalid JSON data: {}", "❌".red(), err);
            std::process::exit(1);
        }
    };

    let token = get_jwt_token(config).await?;
    let client = Client::new();
    let base_url = config.base_url();

    let response = client
        .put(format!("{base_url}/colony-0/pods/{pod}/{subject}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&data)
        .send()
        .await?;

    if response.status().is_success() {
        let result: Value = response.json().await?;
        println!("\n{}", "✅ Data stored successfully!".green().bold());
        print_json_pretty(&result);
    } else {
        let error_text = response.text().await?;
        println!("{} {}", "❌ Failed to store data:".red(), error_text);
        std::process::exit(1);
    }

    Ok(())
}
