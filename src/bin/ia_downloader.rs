use clap::{Arg, Command};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Command::new("ia_downloader")
        .version("0.1.0")
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
                .help("Output directory (default: colony_uploader)")
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

    let _pod = matches.get_one::<String>("pod").unwrap(); // Will be used by colony_uploader.rs
    let url_str = matches.get_one::<String>("url").unwrap();
    let extensions_str = matches.get_one::<String>("extensions").unwrap();
    let output_dir = matches.get_one::<String>("output-dir").unwrap();

    println!("{} {}", "🏛️".bold(), "Internet Archive Downloader".bold().cyan());
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
    println!("{} {}", "📁 Extensions:".bold(), extensions.join(", ").yellow());

    // Create output directory structure
    let base_output_dir = PathBuf::from(output_dir);
    let item_dir = base_output_dir.join(&identifier);
    
    if !base_output_dir.exists() {
        fs::create_dir_all(&base_output_dir)?;
        println!("{} {}", "📂 Created directory:".bold(), base_output_dir.display().to_string().blue());
    }
    
    if !item_dir.exists() {
        fs::create_dir_all(&item_dir)?;
        println!("{} {}", "📂 Created directory:".bold(), item_dir.display().to_string().blue());
    }

    // Initialize HTTP client
    let client = Client::new();

    // Download metadata and files list
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());

    pb.set_message("📥 Downloading metadata...");
    let metadata = download_metadata(&client, &identifier, &item_dir).await?;

    pb.set_message("📋 Downloading files list...");
    let files = download_files_list(&client, &identifier, &item_dir).await?;

    pb.set_message("🖼️ Downloading thumbnail...");
    let thumbnail_address = download_thumbnail(&client, &identifier, &item_dir).await?;
    pb.finish_and_clear();

    println!("{} {}", "✅ Downloaded metadata for:".bold(), metadata.title.green());
    println!("{} {}", "👤 Author:".bold(), metadata.creator.cyan());

    // Show thumbnail status
    if let Some(ref thumb_addr) = thumbnail_address {
        println!("{} {}", "🖼️ Thumbnail:".bold(), format!("ant://{}", thumb_addr).magenta());
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
        // Check for AI enhancement flag
        let ai_enhance = matches.get_flag("ai-enhance");
        enhance_metadata(&client, &metadata, &identifier, ai_enhance).await?
    };

    // Filter files by extensions
    let filtered_files = filter_files_by_extensions(&files, &extensions);
    
    if filtered_files.is_empty() {
        println!("{} No files found with extensions: {}", "⚠️".yellow(), extensions.join(", "));
        return Ok(());
    }

    println!("{} Found {} files to download", "📁".bold(), filtered_files.len().to_string().green());

    // Create extension directories and download files
    for (extension, files_for_ext) in group_files_by_extension(&filtered_files) {
        let ext_dir = item_dir.join(&extension);
        if !ext_dir.exists() {
            fs::create_dir_all(&ext_dir)?;
            println!("{} {}", "📂 Created directory:".bold(), ext_dir.display().to_string().blue());
        }

        for (index, file) in files_for_ext.iter().enumerate() {
            download_file(&client, &identifier, &file, &ext_dir).await?;

            // Get actual downloaded file size
            let file_path = ext_dir.join(&file.name);
            let actual_size = fs::metadata(&file_path)?.len();

            // Calculate Autonomi address
            let autonomi_address = calculate_autonomi_address(&file_path)?;

            // Create JSON-LD metadata with actual file size, index, and thumbnail
            let metadata_index = if files_for_ext.len() > 1 { Some(index + 1) } else { None };
            create_jsonld_metadata(&file, &enhanced_metadata, &autonomi_address, actual_size, metadata_index, &thumbnail_address, &ext_dir).await?;

            println!("{} {} -> {}",
                "✅".green(),
                file.name.bold(),
                format!("ant://{}", autonomi_address).cyan()
            );
        }
    }

    println!();
    println!("{} {}", "🎉 Download completed!".bold().green(), 
        format!("Files saved to: {}", item_dir.display()).blue());
    
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
    let meta_url = format!("https://archive.org/download/{}/{}_meta.xml", identifier, identifier);
    let response = client.get(&meta_url).send().await?;
    
    if !response.status().is_success() {
        anyhow::bail!("Failed to download metadata: HTTP {}", response.status());
    }
    
    let content = response.text().await?;
    let meta_file = output_dir.join(format!("{}_meta.xml", identifier));
    fs::write(&meta_file, &content)?;
    
    // Parse metadata
    parse_metadata(&content)
}

async fn download_files_list(
    client: &Client,
    identifier: &str,
    output_dir: &Path,
) -> anyhow::Result<Vec<FileInfo>> {
    let files_url = format!("https://archive.org/download/{}/{}_files.xml", identifier, identifier);
    let response = client.get(&files_url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download files list: HTTP {}", response.status());
    }

    let content = response.text().await?;
    let files_file = output_dir.join(format!("{}_files.xml", identifier));
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
        let thumbnail_url = format!("https://archive.org/download/{}/__ia_thumb.{}", identifier, format);
        let response = client.get(&thumbnail_url).send().await?;

        if response.status().is_success() {
            let thumbnail_filename = format!("__ia_thumb.{}", format);
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
    use quick_xml::events::Event;
    use quick_xml::Reader;

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
    use quick_xml::events::Event;
    use quick_xml::Reader;
    
    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);
    
    let mut files = Vec::new();
    
    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"file" => {
                let mut name = String::new();
                let mut size = 0u64;
                
                // Parse attributes
                for attr in e.attributes() {
                    let attr = attr?;
                    match attr.key.as_ref() {
                        b"name" => {
                            name = String::from_utf8_lossy(&attr.value).to_string();
                        }
                        b"size" => {
                            if let Ok(size_str) = String::from_utf8_lossy(&attr.value).parse::<u64>() {
                                size = size_str;
                            }
                        }
                        _ => {}
                    }
                }
                
                if !name.is_empty() {
                    if let Some(extension) = Path::new(&name).extension() {
                        let ext_str = extension.to_string_lossy().to_lowercase();
                        files.push(FileInfo {
                            name,
                            extension: ext_str,
                            size,
                        });
                    }
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
) -> anyhow::Result<EnhancedMetadata> {
    println!("{} {}", "🔍 Enhancing metadata...".bold(), "Trying multiple sources".cyan());

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
        if let Ok(ai_description) = get_ai_enhanced_description(client, &enhanced).await {
            enhanced.enhanced_description = Some(ai_description);
            enhanced.source = format!("{} + AI", enhanced.source);
        }
    }

    println!("{} {}", "✅ Metadata enhanced from:".bold(), enhanced.source.green());
    Ok(enhanced)
}

// Internet Archive detailed metadata
async fn get_ia_detailed_metadata(client: &Client, identifier: &str) -> anyhow::Result<serde_json::Value> {
    let url = format!("https://archive.org/metadata/{}", identifier);
    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    } else {
        anyhow::bail!("Failed to get IA detailed metadata: HTTP {}", response.status());
    }
}

fn merge_ia_metadata(mut enhanced: EnhancedMetadata, ia_data: serde_json::Value) -> EnhancedMetadata {
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
async fn get_book_metadata(client: &Client, enhanced: &EnhancedMetadata) -> anyhow::Result<serde_json::Value> {
    // Try searching by title and author
    let query = format!("{} {}", enhanced.title, enhanced.creator);
    let encoded_query = urlencoding::encode(&query);
    let url = format!("https://openlibrary.org/search.json?q={}&limit=1", encoded_query);

    let response = client.get(&url).send().await?;
    if response.status().is_success() {
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    } else {
        anyhow::bail!("Failed to get Open Library metadata: HTTP {}", response.status());
    }
}

fn merge_book_metadata(mut enhanced: EnhancedMetadata, book_data: serde_json::Value) -> EnhancedMetadata {
    if let Some(docs) = book_data.get("docs").and_then(|d| d.as_array()) {
        if let Some(book) = docs.first() {
            // Enhanced description from Open Library
            if let Some(description) = book.get("first_sentence").and_then(|d| d.as_array()) {
                if let Some(first_desc) = description.first().and_then(|d| d.as_str()) {
                    enhanced.enhanced_description = Some(first_desc.to_string());
                }
            }

            // ISBN
            if let Some(isbn) = book.get("isbn").and_then(|i| i.as_array()) {
                if let Some(first_isbn) = isbn.first().and_then(|i| i.as_str()) {
                    enhanced.isbn = Some(first_isbn.to_string());
                }
            }

            // Publisher
            if let Some(publisher) = book.get("publisher").and_then(|p| p.as_array()) {
                if let Some(first_pub) = publisher.first().and_then(|p| p.as_str()) {
                    enhanced.publisher = Some(first_pub.to_string());
                }
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
    }

    enhanced.source = format!("{} + Open Library", enhanced.source);
    enhanced
}

// Movie metadata (stub for now - could integrate with TMDB)
async fn get_movie_metadata(_client: &Client, _enhanced: &EnhancedMetadata) -> anyhow::Result<serde_json::Value> {
    // TODO: Implement TMDB API integration
    anyhow::bail!("Movie metadata enhancement not yet implemented");
}

fn merge_movie_metadata(enhanced: EnhancedMetadata, _movie_data: serde_json::Value) -> EnhancedMetadata {
    // TODO: Implement movie metadata merging
    enhanced
}

// Music metadata (stub for now - could integrate with MusicBrainz)
async fn get_music_metadata(_client: &Client, _enhanced: &EnhancedMetadata) -> anyhow::Result<serde_json::Value> {
    // TODO: Implement MusicBrainz API integration
    anyhow::bail!("Music metadata enhancement not yet implemented");
}

fn merge_music_metadata(enhanced: EnhancedMetadata, _music_data: serde_json::Value) -> EnhancedMetadata {
    // TODO: Implement music metadata merging
    enhanced
}

// Wikipedia metadata
async fn get_wikipedia_metadata(client: &Client, enhanced: &EnhancedMetadata) -> anyhow::Result<serde_json::Value> {
    // Search Wikipedia for the title
    let query = urlencoding::encode(&enhanced.title);
    let url = format!("https://en.wikipedia.org/api/rest_v1/page/summary/{}", query);

    let response = client.get(&url).send().await?;
    if response.status().is_success() {
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    } else {
        anyhow::bail!("Failed to get Wikipedia metadata: HTTP {}", response.status());
    }
}

fn merge_wikipedia_metadata(mut enhanced: EnhancedMetadata, wiki_data: serde_json::Value) -> EnhancedMetadata {
    // Extract Wikipedia summary if we don't have a good description
    if enhanced.enhanced_description.is_none() {
        if let Some(extract) = wiki_data.get("extract").and_then(|e| e.as_str()) {
            if !extract.is_empty() && extract.len() > 100 {
                enhanced.enhanced_description = Some(extract.to_string());
            }
        }
    }

    enhanced.source = format!("{} + Wikipedia", enhanced.source);
    enhanced
}

// AI enhancement using Hugging Face Inference API (free tier)
async fn get_ai_enhanced_description(client: &Client, enhanced: &EnhancedMetadata) -> anyhow::Result<String> {
    // Use Hugging Face's free inference API for text summarization
    let api_url = "https://api-inference.huggingface.co/models/facebook/bart-large-cnn";

    // Prepare the text to summarize (combine title, author, and existing description)
    let input_text = format!(
        "Book: {} by {}. Description: {}",
        enhanced.title,
        enhanced.creator,
        enhanced.description
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

    let response = client
        .post(api_url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(summary) = result.get(0).and_then(|s| s.get("summary_text")).and_then(|s| s.as_str()) {
            Ok(summary.to_string())
        } else {
            anyhow::bail!("Unexpected AI API response format");
        }
    } else {
        anyhow::bail!("AI enhancement failed: HTTP {}", response.status());
    }
}

fn filter_files_by_extensions<'a>(files: &'a [FileInfo], extensions: &[String]) -> Vec<&'a FileInfo> {
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
    let file_url = format!("https://archive.org/download/{}/{}", identifier, encoded_name);

    let pb = ProgressBar::new(file.size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {msg}")
        .unwrap()
        .progress_chars("#>-"));
    pb.set_message(format!("📥 {}", file.name));

    let response = client.get(&file_url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download file {}: HTTP {}", file.name, response.status());
    }

    let file_path = output_dir.join(&file.name);

    // Download the entire file at once for simplicity
    let bytes = response.bytes().await?;
    fs::write(&file_path, &bytes)?;

    pb.set_position(bytes.len() as u64);

    pb.finish_and_clear();
    Ok(())
}

fn calculate_autonomi_address(file_path: &Path) -> anyhow::Result<String> {
    let file_content = fs::read(file_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&file_content);
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
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

    // Use title from metadata as schema:name, fallback to filename if title is empty
    let schema_name = if !metadata.title.is_empty() {
        metadata.title.clone()
    } else {
        file.name.clone()
    };

    // Use enhanced description if available, otherwise fall back to original
    let description = metadata.enhanced_description
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
        format!("metadata_{}.json", index)
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
