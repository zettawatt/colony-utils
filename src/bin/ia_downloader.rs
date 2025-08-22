use autonomi::{client::data::DataAddress, self_encryption::encrypt};
use bytes::Bytes;
use clap::{Arg, Command};
use colored::*;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, Instant};

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Debug)]
struct FileInfo {
    name: String,
    extension: String,
    size: u64,
}

#[derive(Debug)]
struct MetadataInfo {
    creator: String,
    artist: String,
    director: String,
    writer: String,
    description: String,
    title: String,
    mediatype: String,
}

#[derive(Debug, Clone)]
struct EnhancedMetadata {
    title: String,
    description: String,
    creator: String,
    artist: String,
    director: String,
    writer: String,
    mediatype: String,
    // Enhanced fields
    enhanced_description: Option<String>,
    subjects: Vec<String>,
    publication_date: Option<String>,
    publisher: Option<String>,
    isbn: Option<String>,
    language: Option<String>,
    genre: Option<String>,
    source: String, // Which API provided the enhancement
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    // API Keys for enhanced metadata
    huggingface_api_key: Option<String>,
    tmdb_api_key: Option<String>,

    // AI Enhancement settings
    ai_model_url: Option<String>,
    enable_ai_enhancement: bool,

    // Default settings
    default_output_dir: Option<String>,
    max_concurrent_downloads: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            huggingface_api_key: None,
            tmdb_api_key: None,
            ai_model_url: Some(
                "https://api-inference.huggingface.co/models/facebook/bart-large-cnn".to_string(),
            ),
            enable_ai_enhancement: false,
            default_output_dir: Some("colony_uploader".to_string()),
            max_concurrent_downloads: 3,
        }
    }
}

fn load_config() -> Config {
    let config_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ia_downloader")
        .join("config.json");

    if config_path.exists()
        && let Ok(content) = fs::read_to_string(&config_path)
        && let Ok(config) = serde_json::from_str::<Config>(&content)
    {
        return config;
    }

    // Return default config if file doesn't exist or can't be parsed
    Config::default()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let _config = load_config();

    let app = Command::new("ia_downloader")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Chuck McClish")
        .about("🏛️ Internet Archive downloader for colony metadata framework")
        .arg(
            Arg::new("pod")
                .value_name("POD")
                .help("Pod name or address to record metadata in")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("url")
                .value_name("URL")
                .help("Internet Archive URL (e.g., https://archive.org/details/george-orwell-1984_202309)")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("extensions")
                .value_name("EXTENSIONS")
                .help("Comma-separated list of file extensions (e.g., pdf,txt,epub)")
                .required(true)
                .index(3),
        )
        .arg(
            Arg::new("output-dir")
                .short('o')
                .long("output-dir")
                .value_name("DIR")
                .help("Output directory")
                .default_value("colony_uploader"),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable color output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-enhance")
                .long("no-enhance")
                .help("Skip metadata enhancement from external sources")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ai-enhance")
                .long("ai-enhance")
                .help("Enable AI-powered metadata enhancement (requires API access)")
                .action(clap::ArgAction::SetTrue),
        );

    let matches = app.get_matches();

    // Disable colors if requested
    if matches.get_flag("no-color") {
        colored::control::set_override(false);
    }

    let pod_name = matches.get_one::<String>("pod").unwrap();
    let url_str = matches.get_one::<String>("url").unwrap();
    let extensions_str = matches.get_one::<String>("extensions").unwrap();
    let output_dir = matches.get_one::<String>("output-dir").unwrap();

    println!(
        "{} {}",
        "🏛️".bold(),
        "Internet Archive Downloader".bold().cyan()
    );
    println!();

    // Parse and validate URL
    let url = Url::parse(url_str)?;
    if !url.host_str().unwrap_or("").contains("archive.org") {
        anyhow::bail!("URL must be from archive.org");
    }

    // Extract identifier from URL
    let identifier = extract_identifier(&url)?;
    println!("{} {}", "📋 Identifier:".bold(), identifier.green());

    // Parse extensions
    let extensions: Vec<String> = extensions_str
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();
    println!(
        "{} {}",
        "📁 Extensions:".bold(),
        extensions.join(", ").yellow()
    );

    // Create output directory structure
    let base_output_dir = PathBuf::from(output_dir);
    let item_dir = base_output_dir.join(&identifier);

    if !base_output_dir.exists() {
        fs::create_dir_all(&base_output_dir)?;
        println!(
            "{} {}",
            "📂 Created directory:".bold(),
            base_output_dir.display().to_string().blue()
        );
    }

    if !item_dir.exists() {
        fs::create_dir_all(&item_dir)?;
        println!(
            "{} {}",
            "📂 Created directory:".bold(),
            item_dir.display().to_string().blue()
        );
    }

    // Initialize HTTP client
    let client = Client::new();

    // Download metadata and files list
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );

    pb.set_message("📥 Downloading metadata...");
    let metadata = download_metadata(&client, &identifier, &item_dir).await?;

    pb.set_message("📋 Downloading files list...");
    let files = download_files_list(&client, &identifier, &item_dir).await?;

    // Save pod name to file
    let pod_name_file = item_dir.join("pod_name.txt");
    fs::write(&pod_name_file, pod_name)?;
    println!(
        "{} {}",
        "📝 Pod name saved:".bold(),
        pod_name_file.display().to_string().blue()
    );

    pb.set_message("🖼️ Downloading thumbnail...");
    let thumbnail_address = download_thumbnail(&client, &identifier, &item_dir).await?;
    pb.finish_and_clear();

    println!(
        "{} {}",
        "✅ Downloaded metadata for:".bold(),
        metadata.title.green()
    );
    println!("{} {}", "👤 Author:".bold(), metadata.creator.cyan());

    // Show thumbnail status
    if let Some(ref thumb_addr) = thumbnail_address {
        println!(
            "{} {}",
            "🖼️ Thumbnail:".bold(),
            format!("ant://{thumb_addr}").magenta()
        );
    } else {
        println!("{} {}", "🖼️ Thumbnail:".bold(), "Not found".yellow());
    }

    // Enhance metadata with external sources (unless disabled)
    let enhanced_metadata = if matches.get_flag("no-enhance") {
        // Convert basic metadata to enhanced format without external enhancement
        EnhancedMetadata {
            title: metadata.title.clone(),
            description: metadata.description.clone(),
            creator: metadata.creator.clone(),
            artist: metadata.artist.clone(),
            director: metadata.director.clone(),
            writer: metadata.writer.clone(),
            mediatype: metadata.mediatype.clone(),
            enhanced_description: None,
            subjects: Vec::new(),
            publication_date: None,
            publisher: None,
            isbn: None,
            language: None,
            genre: None,
            source: "Internet Archive".to_string(),
        }
    } else {
        // Check for AI enhancement: command line flag OR config file setting
        let ai_enhance = matches.get_flag("ai-enhance") || _config.enable_ai_enhancement;
        if ai_enhance {
            println!(
                "{} {}",
                "🔍 Enhancing metadata...".bold(),
                "Trying multiple sources + AI".yellow()
            );
        } else {
            println!(
                "{} {}",
                "🔍 Enhancing metadata...".bold(),
                "Trying multiple sources".yellow()
            );
        }
        enhance_metadata(&client, &metadata, &identifier, ai_enhance, &_config).await?
    };

    // Filter files by extensions
    let filtered_files = filter_files_by_extensions(&files, &extensions);

    if filtered_files.is_empty() {
        println!(
            "{} No files found with extensions: {}",
            "⚠️".yellow(),
            extensions.join(", ")
        );
        return Ok(());
    }

    println!(
        "{} Found {} files to download",
        "📁".bold(),
        filtered_files.len().to_string().green()
    );

    // Create extension directories and download files
    let mut total_downloaded_size = 0u64;
    let mut downloaded_files_count = 0;

    for (extension, files_for_ext) in group_files_by_extension(&filtered_files) {
        let ext_dir = item_dir.join(&extension);
        if !ext_dir.exists() {
            fs::create_dir_all(&ext_dir)?;
            println!(
                "{} {}",
                "📂 Created directory:".bold(),
                ext_dir.display().to_string().blue()
            );
        }

        for (index, file) in files_for_ext.iter().enumerate() {
            download_file(&client, &identifier, file, &ext_dir).await?;

            // Validate downloaded file
            let file_path = ext_dir.join(&file.name);
            validate_downloaded_file(&file_path, Some(file.size))?;

            // Get actual downloaded file size
            let actual_size = fs::metadata(&file_path)?.len();
            total_downloaded_size += actual_size;
            downloaded_files_count += 1;

            // Calculate Autonomi address
            let autonomi_address = calculate_autonomi_address(&file_path)?;

            // Create JSON-LD metadata with actual file size, index, and thumbnail
            let metadata_index = if files_for_ext.len() > 1 {
                Some(index + 1)
            } else {
                None
            };
            create_jsonld_metadata(
                file,
                &enhanced_metadata,
                &autonomi_address,
                actual_size,
                metadata_index,
                &thumbnail_address,
                &ext_dir,
            )
            .await?;

            println!(
                "{} {} -> {}",
                "✅".green(),
                file.name.bold(),
                format!("ant://{autonomi_address}").cyan()
            );
        }
    }

    // Calculate and display summary statistics
    let total_size_mb = total_downloaded_size as f64 / 1_048_576.0; // Convert to MB

    println!();
    println!("{} ", "📊 Download Summary:".bold().cyan());
    println!(
        "   {} Files downloaded: {}",
        "📁".bold(),
        downloaded_files_count.to_string().green()
    );
    println!(
        "   {} Total size: {:.2} MB ({} bytes)",
        "💾".bold(),
        total_size_mb.to_string().green(),
        total_downloaded_size.to_string().yellow()
    );
    println!(
        "   {} Metadata source: {}",
        "🔍".bold(),
        enhanced_metadata.source.green()
    );
    if thumbnail_address.is_some() {
        println!("   {} Thumbnail: {}", "🖼️".bold(), "Downloaded".green());
    }
    println!();
    println!(
        "{} {}",
        "🎉 Download completed!".bold().green(),
        format!("Files saved to: {}", item_dir.display()).blue()
    );

    Ok(())
}

fn extract_identifier(url: &Url) -> anyhow::Result<String> {
    let path = url.path();

    // Handle both /details/ and /download/ paths
    if let Some(details_pos) = path.find("/details/") {
        let identifier = &path[details_pos + 9..];
        if identifier.is_empty() {
            anyhow::bail!("Could not extract identifier from URL");
        }
        Ok(identifier.to_string())
    } else if let Some(download_pos) = path.find("/download/") {
        let after_download = &path[download_pos + 10..];
        // Extract identifier (everything before the next slash, if any)
        let identifier = if let Some(slash_pos) = after_download.find('/') {
            &after_download[..slash_pos]
        } else {
            after_download
        };
        if identifier.is_empty() {
            anyhow::bail!("Could not extract identifier from URL");
        }
        Ok(identifier.to_string())
    } else {
        anyhow::bail!("URL must contain '/details/' or '/download/' path");
    }
}

async fn download_metadata(
    client: &Client,
    identifier: &str,
    output_dir: &Path,
) -> anyhow::Result<MetadataInfo> {
    let meta_url = format!("https://archive.org/download/{identifier}/{identifier}_meta.xml");
    let response = client.get(&meta_url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download metadata: HTTP {}", response.status());
    }

    let content = response.text().await?;
    let meta_file = output_dir.join(format!("{identifier}_meta.xml"));
    fs::write(&meta_file, &content)?;

    // Parse metadata
    parse_metadata(&content)
}

async fn download_files_list(
    client: &Client,
    identifier: &str,
    output_dir: &Path,
) -> anyhow::Result<Vec<FileInfo>> {
    let files_url = format!("https://archive.org/download/{identifier}/{identifier}_files.xml");
    let response = client.get(&files_url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download files list: HTTP {}", response.status());
    }

    let content = response.text().await?;
    let files_file = output_dir.join(format!("{identifier}_files.xml"));
    fs::write(&files_file, &content)?;

    // Parse files list
    parse_files_list(&content)
}

async fn download_thumbnail(
    client: &Client,
    identifier: &str,
    output_dir: &Path,
) -> anyhow::Result<Option<String>> {
    // Try common thumbnail formats - Internet Archive uses __ia_thumb.jpg pattern
    let thumbnail_formats = ["jpg", "jpeg", "png", "gif"];

    for format in &thumbnail_formats {
        let thumbnail_url =
            format!("https://archive.org/download/{identifier}/__ia_thumb.{format}");
        let response = client.get(&thumbnail_url).send().await?;

        if response.status().is_success() {
            let thumbnail_filename = format!("__ia_thumb.{format}");
            let thumbnail_path = output_dir.join(&thumbnail_filename);

            // Download the thumbnail
            let bytes = response.bytes().await?;
            fs::write(&thumbnail_path, &bytes)?;

            // Calculate Autonomi address for the thumbnail
            let autonomi_address = calculate_autonomi_address(&thumbnail_path)?;

            return Ok(Some(autonomi_address));
        }
    }

    // If no thumbnail found, return None
    Ok(None)
}

fn parse_metadata(xml_content: &str) -> anyhow::Result<MetadataInfo> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut creator = String::new();
    let mut artist = String::new();
    let mut director = String::new();
    let mut writer = String::new();
    let mut description = String::new();
    let mut title = String::new();
    let mut mediatype = String::new();
    let mut current_tag = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape()?.to_string();
                match current_tag.as_str() {
                    "creator" => creator = text,
                    "artist" => artist = text,
                    "director" => director = text,
                    "writer" => writer = text,
                    "description" => description = text,
                    "title" => title = text,
                    "mediatype" => mediatype = text,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => anyhow::bail!("Error parsing metadata XML: {}", e),
            _ => {}
        }
    }

    Ok(MetadataInfo {
        creator,
        artist,
        director,
        writer,
        description,
        title,
        mediatype,
    })
}

fn parse_files_list(xml_content: &str) -> anyhow::Result<Vec<FileInfo>> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut files = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"file" => {
                let mut name = String::new();
                let mut size = 0u64;

                // Parse attributes (name is an attribute)
                for attr in e.attributes() {
                    let attr = attr?;
                    if attr.key.as_ref() == b"name" {
                        name = String::from_utf8_lossy(&attr.value).to_string();
                    }
                }

                // Parse child elements (size is a child element)
                let mut current_tag = String::new();
                loop {
                    match reader.read_event() {
                        Ok(Event::Start(ref e)) => {
                            current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        }
                        Ok(Event::Text(e)) => {
                            let text = e.unescape()?.to_string();
                            if current_tag == "size"
                                && let Ok(size_val) = text.parse::<u64>()
                            {
                                size = size_val;
                            }
                        }
                        Ok(Event::End(ref e)) if e.name().as_ref() == b"file" => {
                            break; // End of this file element
                        }
                        Ok(Event::Eof) => break,
                        Err(e) => anyhow::bail!("Error parsing files XML: {}", e),
                        _ => {}
                    }
                }

                if !name.is_empty()
                    && let Some(extension) = Path::new(&name).extension()
                {
                    let ext_str = extension.to_string_lossy().to_lowercase();
                    files.push(FileInfo {
                        name,
                        extension: ext_str,
                        size,
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => anyhow::bail!("Error parsing files XML: {}", e),
            _ => {}
        }
    }

    Ok(files)
}

// Metadata Enhancement System
async fn enhance_metadata(
    client: &Client,
    base_metadata: &MetadataInfo,
    identifier: &str,
    ai_enhance: bool,
    config: &Config,
) -> anyhow::Result<EnhancedMetadata> {
    let mut enhanced = EnhancedMetadata {
        title: base_metadata.title.clone(),
        description: base_metadata.description.clone(),
        creator: base_metadata.creator.clone(),
        artist: base_metadata.artist.clone(),
        director: base_metadata.director.clone(),
        writer: base_metadata.writer.clone(),
        mediatype: base_metadata.mediatype.clone(),
        enhanced_description: None,
        subjects: Vec::new(),
        publication_date: None,
        publisher: None,
        isbn: None,
        language: None,
        genre: None,
        source: "Internet Archive".to_string(),
    };

    // Try Internet Archive's detailed metadata API first
    if let Ok(ia_enhanced) = get_ia_detailed_metadata(client, identifier).await {
        enhanced = merge_ia_metadata(enhanced, ia_enhanced);
    }

    // Try domain-specific APIs based on media type
    match base_metadata.mediatype.as_str() {
        "texts" => {
            if let Ok(book_enhanced) = get_book_metadata(client, &enhanced).await {
                enhanced = merge_book_metadata(enhanced, book_enhanced);
            }
        }
        "movies" => {
            if let Ok(movie_enhanced) = get_movie_metadata(client, &enhanced).await {
                enhanced = merge_movie_metadata(enhanced, movie_enhanced);
            }
        }
        "audio" => {
            if let Ok(music_enhanced) = get_music_metadata(client, &enhanced).await {
                enhanced = merge_music_metadata(enhanced, music_enhanced);
            }
        }
        _ => {}
    }

    // Try Wikipedia/Wikidata for additional context
    if let Ok(wiki_enhanced) = get_wikipedia_metadata(client, &enhanced).await {
        enhanced = merge_wikipedia_metadata(enhanced, wiki_enhanced);
    }

    // Optional: AI enhancement for description (if enabled)
    if ai_enhance {
        let model_name = config
            .ai_model_url
            .as_ref()
            .and_then(|url| url.split('/').next_back())
            .unwrap_or("default");

        match get_ai_enhanced_description(client, &enhanced, config).await {
            Ok(ai_description) => {
                enhanced.enhanced_description = Some(ai_description);
                enhanced.source = format!("{} + AI", enhanced.source);
                println!(
                    "{} {} ({})",
                    "✅".green(),
                    "AI enhancement successful".green(),
                    model_name.cyan()
                );
            }
            Err(e) => {
                println!(
                    "{} {} ({}): {}",
                    "⚠️".yellow(),
                    "AI enhancement failed".yellow(),
                    model_name.cyan(),
                    e.to_string().red()
                );
            }
        }
    }

    println!(
        "{} {}",
        "✅ Metadata enhanced from:".bold(),
        enhanced.source.green()
    );
    Ok(enhanced)
}

// Internet Archive detailed metadata
async fn get_ia_detailed_metadata(
    client: &Client,
    identifier: &str,
) -> anyhow::Result<serde_json::Value> {
    let url = format!("https://archive.org/metadata/{identifier}");
    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    } else {
        anyhow::bail!(
            "Failed to get IA detailed metadata: HTTP {}",
            response.status()
        );
    }
}

fn merge_ia_metadata(
    mut enhanced: EnhancedMetadata,
    ia_data: serde_json::Value,
) -> EnhancedMetadata {
    if let Some(metadata) = ia_data.get("metadata") {
        // Extract subjects/tags
        if let Some(subjects) = metadata.get("subject") {
            if let Some(subjects_array) = subjects.as_array() {
                enhanced.subjects = subjects_array
                    .iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect();
            } else if let Some(subject_str) = subjects.as_str() {
                enhanced.subjects = vec![subject_str.to_string()];
            }
        }

        // Extract publication date
        if let Some(date) = metadata.get("date").and_then(|d| d.as_str()) {
            enhanced.publication_date = Some(date.to_string());
        }

        // Extract language
        if let Some(language) = metadata.get("language").and_then(|l| l.as_str()) {
            enhanced.language = Some(language.to_string());
        }

        // Extract publisher
        if let Some(publisher) = metadata.get("publisher").and_then(|p| p.as_str()) {
            enhanced.publisher = Some(publisher.to_string());
        }
    }

    enhanced.source = "Internet Archive (Enhanced)".to_string();
    enhanced
}

// Book metadata from Open Library
async fn get_book_metadata(
    client: &Client,
    enhanced: &EnhancedMetadata,
) -> anyhow::Result<serde_json::Value> {
    // Try searching by title and author
    let query = format!("{} {}", enhanced.title, enhanced.creator);
    let encoded_query = urlencoding::encode(&query);
    let url = format!("https://openlibrary.org/search.json?q={encoded_query}&limit=1");

    let response = client.get(&url).send().await?;
    if response.status().is_success() {
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    } else {
        anyhow::bail!(
            "Failed to get Open Library metadata: HTTP {}",
            response.status()
        );
    }
}

fn merge_book_metadata(
    mut enhanced: EnhancedMetadata,
    book_data: serde_json::Value,
) -> EnhancedMetadata {
    if let Some(docs) = book_data.get("docs").and_then(|d| d.as_array())
        && let Some(book) = docs.first()
    {
        // Enhanced description from Open Library
        if let Some(description) = book.get("first_sentence").and_then(|d| d.as_array())
            && let Some(first_desc) = description.first().and_then(|d| d.as_str())
        {
            enhanced.enhanced_description = Some(first_desc.to_string());
        }

        // ISBN
        if let Some(isbn) = book.get("isbn").and_then(|i| i.as_array())
            && let Some(first_isbn) = isbn.first().and_then(|i| i.as_str())
        {
            enhanced.isbn = Some(first_isbn.to_string());
        }

        // Publisher
        if let Some(publisher) = book.get("publisher").and_then(|p| p.as_array())
            && let Some(first_pub) = publisher.first().and_then(|p| p.as_str())
        {
            enhanced.publisher = Some(first_pub.to_string());
        }

        // Publication date
        if let Some(pub_date) = book.get("first_publish_year").and_then(|d| d.as_i64()) {
            enhanced.publication_date = Some(pub_date.to_string());
        }

        // Subjects/genres
        if let Some(subjects) = book.get("subject").and_then(|s| s.as_array()) {
            let mut book_subjects: Vec<String> = subjects
                .iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .take(10) // Limit to first 10 subjects
                .collect();
            enhanced.subjects.append(&mut book_subjects);
            enhanced.subjects.dedup(); // Remove duplicates
        }
    }

    enhanced.source = format!("{} + Open Library", enhanced.source);
    enhanced
}

// Movie metadata (stub for now - could integrate with TMDB)
async fn get_movie_metadata(
    _client: &Client,
    _enhanced: &EnhancedMetadata,
) -> anyhow::Result<serde_json::Value> {
    // TODO: Implement TMDB API integration
    anyhow::bail!("Movie metadata enhancement not yet implemented");
}

fn merge_movie_metadata(
    enhanced: EnhancedMetadata,
    _movie_data: serde_json::Value,
) -> EnhancedMetadata {
    // TODO: Implement movie metadata merging
    enhanced
}

// Music metadata (stub for now - could integrate with MusicBrainz)
async fn get_music_metadata(
    _client: &Client,
    _enhanced: &EnhancedMetadata,
) -> anyhow::Result<serde_json::Value> {
    // TODO: Implement MusicBrainz API integration
    anyhow::bail!("Music metadata enhancement not yet implemented");
}

fn merge_music_metadata(
    enhanced: EnhancedMetadata,
    _music_data: serde_json::Value,
) -> EnhancedMetadata {
    // TODO: Implement music metadata merging
    enhanced
}

// Wikipedia metadata
async fn get_wikipedia_metadata(
    client: &Client,
    enhanced: &EnhancedMetadata,
) -> anyhow::Result<serde_json::Value> {
    // Search Wikipedia for the title
    let query = urlencoding::encode(&enhanced.title);
    let url = format!("https://en.wikipedia.org/api/rest_v1/page/summary/{query}");

    let response = client.get(&url).send().await?;
    if response.status().is_success() {
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    } else {
        anyhow::bail!(
            "Failed to get Wikipedia metadata: HTTP {}",
            response.status()
        );
    }
}

fn merge_wikipedia_metadata(
    mut enhanced: EnhancedMetadata,
    wiki_data: serde_json::Value,
) -> EnhancedMetadata {
    // Extract Wikipedia summary if we don't have a good description
    if enhanced.enhanced_description.is_none()
        && let Some(extract) = wiki_data.get("extract").and_then(|e| e.as_str())
        && !extract.is_empty()
        && extract.len() > 100
    {
        enhanced.enhanced_description = Some(extract.to_string());
    }

    enhanced.source = format!("{} + Wikipedia", enhanced.source);
    enhanced
}

// AI enhancement using Hugging Face Inference API (free tier)
async fn get_ai_enhanced_description(
    client: &Client,
    enhanced: &EnhancedMetadata,
    config: &Config,
) -> anyhow::Result<String> {
    // Use configurable AI model URL from config, with fallback to default
    let default_model_url = "https://api-inference.huggingface.co/models/facebook/bart-large-cnn";
    let api_url = config.ai_model_url.as_deref().unwrap_or(default_model_url);

    // Prepare the text to summarize (combine title, author, and existing description)
    let input_text = format!(
        "Book: {} by {}. Description: {}",
        enhanced.title, enhanced.creator, enhanced.description
    );

    // Limit input text to avoid API limits
    let truncated_input = if input_text.len() > 1000 {
        format!("{}...", &input_text[..1000])
    } else {
        input_text
    };

    let payload = json!({
        "inputs": truncated_input,
        "parameters": {
            "max_length": 200,
            "min_length": 50,
            "do_sample": false
        }
    });

    // Check if we have an API key
    let api_key = config
        .huggingface_api_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Hugging Face API key not found in config"))?;

    let response = client
        .post(api_url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(summary) = result
            .get(0)
            .and_then(|s| s.get("summary_text"))
            .and_then(|s| s.as_str())
        {
            Ok(summary.to_string())
        } else {
            anyhow::bail!("Unexpected AI API response format");
        }
    } else {
        anyhow::bail!("AI enhancement failed: HTTP {}", response.status());
    }
}

fn filter_files_by_extensions<'a>(
    files: &'a [FileInfo],
    extensions: &[String],
) -> Vec<&'a FileInfo> {
    files
        .iter()
        .filter(|file| extensions.contains(&file.extension))
        .collect()
}

fn group_files_by_extension<'a>(files: &[&'a FileInfo]) -> HashMap<String, Vec<&'a FileInfo>> {
    let mut grouped = HashMap::new();

    for file in files {
        grouped
            .entry(file.extension.clone())
            .or_insert_with(Vec::new)
            .push(*file);
    }

    grouped
}

async fn download_file(
    client: &Client,
    identifier: &str,
    file: &FileInfo,
    output_dir: &Path,
) -> anyhow::Result<()> {
    let encoded_name = urlencoding::encode(&file.name);
    let file_url = format!("https://archive.org/download/{identifier}/{encoded_name}");

    // Use actual file size if available, otherwise show indeterminate progress
    let pb = if file.size > 0 {
        let pb = ProgressBar::new(file.size);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {msg}")
            .unwrap()
            .progress_chars("#>-"));
        pb.set_message(format!("📥 {}", file.name));
        pb
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {bytes} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("📥 {}", file.name));
        pb
    };

    let response = client.get(&file_url).send().await?;

    if !response.status().is_success() {
        pb.finish_and_clear();
        anyhow::bail!(
            "Failed to download file {}: HTTP {}",
            file.name,
            response.status()
        );
    }

    let file_path = output_dir.join(&file.name);

    // Create the file for writing
    let mut output_file = File::create(&file_path).await?;

    // Shared progress tracking
    let downloaded_bytes = Arc::new(AtomicU64::new(0));
    let file_size = file.size;
    let file_name = file.name.clone();

    // Clone for the progress thread
    let pb_clone = pb.clone();
    let downloaded_clone = downloaded_bytes.clone();

    // Spawn progress update thread that runs every second
    let progress_handle = tokio::spawn(async move {
        let mut last_bytes = 0u64;
        let mut last_time = Instant::now();

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let current_bytes = downloaded_clone.load(Ordering::Relaxed);
            let current_time = Instant::now();

            // Calculate speed
            let bytes_diff = current_bytes.saturating_sub(last_bytes);
            let time_diff = current_time.duration_since(last_time).as_secs_f64();
            let speed = if time_diff > 0.0 {
                bytes_diff as f64 / time_diff
            } else {
                0.0
            };

            // Update message with speed info
            let speed_str = if speed > 1_048_576.0 {
                format!("{:.1} MB/s", speed / 1_048_576.0)
            } else if speed > 1024.0 {
                format!("{:.1} KB/s", speed / 1024.0)
            } else {
                format!("{speed:.0} B/s")
            };

            pb_clone.set_message(format!("📥 {file_name} ({speed_str})"));

            last_bytes = current_bytes;
            last_time = current_time;

            // Exit if download is complete
            if file_size > 0 && current_bytes >= file_size {
                break;
            }
        }
    });

    // Stream the response body and write chunks directly to disk
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;

        // Write chunk to disk immediately
        output_file.write_all(&chunk).await?;

        // Update shared progress counter and progress bar
        let new_total =
            downloaded_bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed) + chunk.len() as u64;
        pb.set_position(new_total);
    }

    // Ensure all data is written to disk
    output_file.flush().await?;

    // Stop the progress thread
    progress_handle.abort();

    // Final progress update
    let final_downloaded = downloaded_bytes.load(Ordering::Relaxed);
    pb.set_position(final_downloaded);
    pb.finish_and_clear();

    Ok(())
}

fn validate_downloaded_file(file_path: &Path, expected_size: Option<u64>) -> anyhow::Result<()> {
    if !file_path.exists() {
        anyhow::bail!("Downloaded file does not exist: {}", file_path.display());
    }

    let actual_size = fs::metadata(file_path)?.len();

    if let Some(expected) = expected_size
        && actual_size != expected
        && expected > 0
    {
        println!("⚠️  File size mismatch: expected {expected} bytes, got {actual_size} bytes");
    }

    if actual_size == 0 {
        anyhow::bail!("Downloaded file is empty: {}", file_path.display());
    }

    Ok(())
}

fn calculate_autonomi_address(file_path: &Path) -> anyhow::Result<String> {
    let file_content = fs::read(file_path)?;

    // Use Autonomi's proper address calculation
    // This follows the same process as data_put_public: encrypt the data and get the data map chunk address
    let bytes = Bytes::from(file_content);
    let (data_map_chunk, _chunks) = encrypt(bytes)?;
    let map_xor_name = *data_map_chunk.address().xorname();
    let data_address = DataAddress::new(map_xor_name);
    Ok(hex::encode(data_address.xorname().0))
}

async fn create_jsonld_metadata(
    file: &FileInfo,
    metadata: &EnhancedMetadata,
    autonomi_address: &str,
    actual_file_size: u64,
    metadata_index: Option<usize>,
    thumbnail_address: &Option<String>,
    output_dir: &Path,
) -> anyhow::Result<()> {
    let encoding_format = get_encoding_format(&file.extension);
    let schema_type = get_schema_type(&metadata.mediatype);
    let author = get_best_author_enhanced(metadata);

    // Always use filename as schema:name
    let schema_name = file.name.clone();

    // Use enhanced description if available, otherwise fall back to original
    let description = metadata
        .enhanced_description
        .as_ref()
        .unwrap_or(&metadata.description)
        .clone();

    // Build JSON-LD object with enhanced metadata
    let mut jsonld_obj = json!({
        "@context": {"schema": "http://schema.org/"},
        "@type": schema_type,
        "@id": format!("ant://{}", autonomi_address),
        "schema:name": schema_name,
        "schema:description": description,
        "schema:author": author,
        "schema:contentSize": actual_file_size.to_string(),
        "schema:encodingFormat": encoding_format
    });

    // Add title as alternateName if available and not empty
    if !metadata.title.is_empty() {
        jsonld_obj["schema:alternateName"] = json!(metadata.title);
    }

    // Add enhanced fields if available
    if let Some(ref isbn) = metadata.isbn {
        jsonld_obj["schema:isbn"] = json!(isbn);
    }

    if let Some(ref publisher) = metadata.publisher {
        jsonld_obj["schema:publisher"] = json!(publisher);
    }

    if let Some(ref pub_date) = metadata.publication_date {
        jsonld_obj["schema:datePublished"] = json!(pub_date);
    }

    if let Some(ref language) = metadata.language {
        jsonld_obj["schema:inLanguage"] = json!(language);
    }

    if let Some(ref genre) = metadata.genre {
        jsonld_obj["schema:genre"] = json!(genre);
    }

    if !metadata.subjects.is_empty() {
        jsonld_obj["schema:keywords"] = json!(metadata.subjects.join(", "));
    }

    // Add thumbnail image if available
    if let Some(thumb_addr) = thumbnail_address {
        jsonld_obj["schema:image"] = json!(format!("ant://{}", thumb_addr));
    }

    // Create filename with index if there are multiple files of the same type
    let metadata_filename = if let Some(index) = metadata_index {
        format!("metadata_{index}.json")
    } else {
        "metadata.json".to_string()
    };

    let metadata_file = output_dir.join(metadata_filename);
    let pretty_json = serde_json::to_string_pretty(&jsonld_obj)?;
    fs::write(metadata_file, pretty_json)?;

    Ok(())
}

fn get_encoding_format(extension: &str) -> &'static str {
    match extension {
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "epub" => "application/epub+zip",
        "html" => "text/html",
        "xml" => "application/xml",
        "json" => "application/json",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

fn get_schema_type(mediatype: &str) -> &'static str {
    match mediatype {
        "texts" => "schema:Book",
        "movies" => "schema:Movie",
        "audio" => "schema:AudioObject",
        "image" => "schema:ImageObject",
        "software" => "schema:SoftwareApplication",
        "data" => "schema:Dataset",
        _ => "schema:CreativeWork",
    }
}

fn get_best_author_enhanced(metadata: &EnhancedMetadata) -> String {
    match metadata.mediatype.as_str() {
        "audio" => {
            // For audio, prefer artist, then creator
            if !metadata.artist.is_empty() {
                metadata.artist.clone()
            } else if !metadata.creator.is_empty() {
                metadata.creator.clone()
            } else {
                "Unknown Artist".to_string()
            }
        }
        "movies" => {
            // For movies, prefer director, then writer, then creator
            if !metadata.director.is_empty() {
                metadata.director.clone()
            } else if !metadata.writer.is_empty() {
                metadata.writer.clone()
            } else if !metadata.creator.is_empty() {
                metadata.creator.clone()
            } else {
                "Unknown Director".to_string()
            }
        }
        _ => {
            // For other types (texts, images, etc.), prefer creator
            if !metadata.creator.is_empty() {
                metadata.creator.clone()
            } else if !metadata.artist.is_empty() {
                metadata.artist.clone()
            } else if !metadata.writer.is_empty() {
                metadata.writer.clone()
            } else if !metadata.director.is_empty() {
                metadata.director.clone()
            } else {
                "Unknown Author".to_string()
            }
        }
    }
}
