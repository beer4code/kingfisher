use anyhow::{Context, Result};
use futures::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tracing::warn;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct SlackMessage {
    pub permalink: String,
    pub text: Option<String>,
    pub ts: String,
    pub channel: SlackChannel,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct SlackChannel {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackPagination {
    page: Option<u32>,
    page_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SlackMessages {
    matches: Vec<SlackMessage>,
    pagination: Option<SlackPagination>,
}

#[derive(Debug, Deserialize)]
struct SlackSearchResponse {
    ok: bool,
    error: Option<String>,
    messages: Option<SlackMessages>,
}

#[derive(Debug, Deserialize)]
pub struct SlackFile {
    id: String,
    name: Option<String>,
    title: Option<String>,
    permalink: Option<String>,
    url_private: Option<String>,
    url_private_download: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackFiles {
    matches: Vec<SlackFile>,
    pagination: Option<SlackPagination>,
}

#[derive(Debug, Deserialize)]
struct SlackFileSearchResponse {
    ok: bool,
    error: Option<String>,
    files: Option<SlackFiles>,
}

fn slack_token() -> Result<String> {
    std::env::var("KF_SLACK_TOKEN").context("KF_SLACK_TOKEN environment variable must be set")
}

fn slack_client(ignore_certs: bool) -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")
}

fn slack_api_error(error: Option<String>) -> anyhow::Error {
    let error = error.unwrap_or_else(|| "unknown".to_string());
    match error.as_str() {
        "not_allowed_token_type" => anyhow::anyhow!(
            "Slack API error: not_allowed_token_type - use a user token with the `search:read` \
             scope"
        ),
        "missing_scope" => anyhow::anyhow!(
            "Slack API error: missing_scope - Slack search requires `search:read` and file \
             downloads require `files:read`"
        ),
        _ => anyhow::anyhow!("Slack API error: {error}"),
    }
}

pub async fn search_messages(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<SlackMessage>> {
    if max_results == 0 {
        return Ok(Vec::new());
    }

    let token = slack_token()?;
    let client = slack_client(ignore_certs)?;
    let mut page = 1u32;
    let mut messages = Vec::new();

    loop {
        let url = api_url.join("search.messages").context("Failed to build Slack API URL")?;

        let resp = client
            .get(url)
            .bearer_auth(&token)
            .query(&[("query", query), ("count", "100"), ("page", &page.to_string())])
            .send()
            .await
            .context("Failed to send Slack request")?;

        let body: SlackSearchResponse =
            resp.json().await.context("Failed to parse Slack response")?;

        if !body.ok {
            return Err(slack_api_error(body.error));
        }

        let Some(msgs) = body.messages else {
            break;
        };
        for m in msgs.matches {
            messages.push(m);
            if messages.len() >= max_results {
                return Ok(messages);
            }
        }
        let next_page =
            msgs.pagination.as_ref().and_then(|p| p.page).map(|p| p + 1).unwrap_or(page + 1);
        let page_count = msgs.pagination.as_ref().and_then(|p| p.page_count).unwrap_or(next_page);
        if next_page > page_count {
            break;
        }
        page = next_page;
    }

    Ok(messages)
}

pub async fn search_files(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<SlackFile>> {
    if max_results == 0 {
        return Ok(Vec::new());
    }

    let token = slack_token()?;
    let client = slack_client(ignore_certs)?;
    let mut page = 1u32;
    let mut files = Vec::new();

    loop {
        let url = api_url.join("search.files").context("Failed to build Slack API URL")?;

        let resp = client
            .get(url)
            .bearer_auth(&token)
            .query(&[("query", query), ("count", "100"), ("page", &page.to_string())])
            .send()
            .await
            .context("Failed to send Slack file search request")?;

        let body: SlackFileSearchResponse =
            resp.json().await.context("Failed to parse Slack file search response")?;

        if !body.ok {
            return Err(slack_api_error(body.error));
        }

        let Some(file_results) = body.files else {
            break;
        };
        for file in file_results.matches {
            files.push(file);
            if files.len() >= max_results {
                return Ok(files);
            }
        }
        let next_page = file_results
            .pagination
            .as_ref()
            .and_then(|p| p.page)
            .map(|p| p + 1)
            .unwrap_or(page + 1);
        let page_count =
            file_results.pagination.as_ref().and_then(|p| p.page_count).unwrap_or(next_page);
        if next_page > page_count {
            break;
        }
        page = next_page;
    }

    Ok(files)
}

fn sanitize_filename_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();

    let trimmed = sanitized.trim_matches([' ', '.']);
    if trimmed.is_empty() { "file".to_string() } else { trimmed.to_string() }
}

pub async fn download_messages_to_dir(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<(PathBuf, String)>> {
    tokio::fs::create_dir_all(output_dir).await?;
    let messages = search_messages(api_url, query, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for msg in messages {
        let ts = msg.ts.replace('.', "_");
        let file = output_dir.join(format!("{}_{}.json", msg.channel.id, ts));
        tokio::fs::write(&file, serde_json::to_vec(&msg)?).await?;
        paths.push((file, msg.permalink));
    }
    Ok(paths)
}

pub async fn download_files_to_dir(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<(PathBuf, String)>> {
    tokio::fs::create_dir_all(output_dir).await?;
    let files = search_files(api_url, query, max_results, ignore_certs).await?;
    let token = slack_token()?;
    let client = slack_client(ignore_certs)?;
    let mut paths = Vec::new();

    for file in files {
        let Some(download_url) =
            file.url_private_download.as_deref().or(file.url_private.as_deref())
        else {
            warn!("Skipping Slack file {} because it has no downloadable URL", file.id);
            continue;
        };

        let response = client
            .get(download_url)
            .bearer_auth(&token)
            .send()
            .await
            .with_context(|| format!("Failed to download Slack file {}", file.id))?
            .error_for_status()
            .with_context(|| {
                format!(
                    "Failed to download Slack file {}; ensure the token has the `files:read` scope",
                    file.id
                )
            })?;

        let original_name = file.name.as_deref().or(file.title.as_deref()).unwrap_or("file");
        let filename = format!(
            "{}_{}",
            sanitize_filename_component(&file.id),
            sanitize_filename_component(original_name)
        );
        let path = output_dir.join(filename);
        let mut output = tokio::fs::File::create(&path)
            .await
            .with_context(|| format!("Failed to create Slack file download {}", path.display()))?;
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk
                .with_context(|| format!("Failed while downloading Slack file {}", file.id))?;
            output.write_all(&chunk).await.with_context(|| {
                format!("Failed to write Slack file download {}", path.display())
            })?;
        }
        output
            .flush()
            .await
            .with_context(|| format!("Failed to flush Slack file download {}", path.display()))?;

        paths.push((path, file.permalink.unwrap_or_default()));
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::sanitize_filename_component;

    #[test]
    fn sanitize_filename_component_prevents_path_traversal() {
        assert_eq!(sanitize_filename_component("../../secrets.txt"), "_.._secrets.txt");
        assert_eq!(sanitize_filename_component(".."), "file");
        assert_eq!(sanitize_filename_component("a:b\\c"), "a_b_c");
    }
}
