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
            create_jsonld_metadata(&file, &metadata, &autonomi_address, actual_size, metadata_index, &thumbnail_address, &ext_dir).await?;

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
    metadata: &MetadataInfo,
    autonomi_address: &str,
    actual_file_size: u64,
    metadata_index: Option<usize>,
    thumbnail_address: &Option<String>,
    output_dir: &Path,
) -> anyhow::Result<()> {
    let encoding_format = get_encoding_format(&file.extension);
    let schema_type = get_schema_type(&metadata.mediatype);
    let author = get_best_author(metadata, &metadata.mediatype);

    // Use title from metadata as schema:name, fallback to filename if title is empty
    let schema_name = if !metadata.title.is_empty() {
        metadata.title.clone()
    } else {
        file.name.clone()
    };

    // Build JSON-LD object
    let mut jsonld_obj = json!({
        "@context": {"schema": "http://schema.org/"},
        "@type": schema_type,
        "@id": format!("ant://{}", autonomi_address),
        "schema:name": schema_name,
        "schema:description": metadata.description,
        "schema:author": author,
        "schema:contentSize": actual_file_size.to_string(),
        "schema:encodingFormat": encoding_format
    });

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

fn get_best_author(metadata: &MetadataInfo, mediatype: &str) -> String {
    match mediatype {
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
