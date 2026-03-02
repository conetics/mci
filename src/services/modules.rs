use crate::{database, models, schema, utils};
use anyhow::{Context, Result};
use aws_sdk_s3;
use aws_smithy_types::byte_stream;
use diesel::prelude::*;
use futures::stream::TryStreamExt;
use http_body_util::StreamBody;
use reqwest;
use serde::{Deserialize, Serialize};
use tokio::fs;

#[derive(Debug, Deserialize)]
pub enum SortBy {
    Id,
    Name,
    Type,
}

#[derive(Debug, Deserialize)]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(Debug, Deserialize, Default)]
pub struct ModuleFilter {
    pub query: Option<String>,
    pub is_enabled: Option<bool>,
    pub r#type: Option<models::ModuleType>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
    pub sort_by: Option<SortBy>,
    pub sort_order: Option<SortOrder>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ModulePayload {
    pub id: String,
    pub name: String,
    pub r#type: models::ModuleType,
    pub description: String,
    pub file_url: String,
    pub digest: String,
    pub source_url: Option<String>,
}

async fn fetch_module(
    http_client: &reqwest::Client,
    source: &utils::source::Source,
) -> Result<ModulePayload> {
    match source {
        utils::source::Source::Http(url) => {
            let module_payload = http_client
                .get(url)
                .header("User-Agent", "MCI/1.0")
                .send()
                .await
                .context("Failed to send HTTP request")?
                .error_for_status()
                .context("HTTP request returned error status")?
                .json::<ModulePayload>()
                .await
                .context("Failed to parse module JSON from response")?;
            Ok(module_payload)
        }
        utils::source::Source::File(path) => {
            let content = fs::read_to_string(path)
                .await
                .context("Failed to read module file")?;
            let module_payload = serde_json::from_str::<ModulePayload>(&content)
                .context("Failed to parse module JSON")?;
            Ok(module_payload)
        }
    }
}

fn db_update_module(
    conn: &mut database::DbConnection,
    module_id: &str,
    update_module: &models::UpdateModule,
) -> QueryResult<models::Module> {
    diesel::update(schema::modules::table.find(module_id))
        .set(update_module)
        .returning(models::Module::as_returning())
        .get_result(conn)
}

pub fn get_module(
    conn: &mut database::DbConnection,
    module_id: &str,
) -> QueryResult<models::Module> {
    schema::modules::table
        .find(module_id)
        .select(models::Module::as_select())
        .first(conn)
}

pub async fn delete_module(
    conn: &mut database::DbConnection,
    s3_client: &aws_sdk_s3::Client,
    module_id: &str,
) -> Result<usize> {
    let prefix = format!("{}/", module_id);
    utils::s3::delete_objects_with_prefix(s3_client, "modules", &prefix).await?;
    Ok(diesel::delete(schema::modules::table.find(module_id)).execute(conn)?)
}

pub fn update_module(
    conn: &mut database::DbConnection,
    module_id: &str,
    update_module: &models::UpdateModule,
) -> QueryResult<models::Module> {
    db_update_module(conn, module_id, update_module)
}

pub fn list_modules(
    conn: &mut database::DbConnection,
    filter: &ModuleFilter,
) -> QueryResult<Vec<models::Module>> {
    use crate::schema::modules::dsl::*;

    let mut query = schema::modules::table.into_boxed();

    if let Some(ref search_query) = filter.query {
        query = query.filter(
            id.ilike(format!("%{}%", search_query))
                .or(name.ilike(format!("%{}%", search_query)))
                .or(description.ilike(format!("%{}%", search_query))),
        );
    }

    if let Some(enabled_filter) = filter.is_enabled {
        query = query.filter(is_enabled.eq(enabled_filter));
    }
    if let Some(ref module_type_filter) = filter.r#type {
        query = query.filter(type_.eq(module_type_filter));
    }

    match (&filter.sort_by, &filter.sort_order) {
        (Some(SortBy::Id), Some(SortOrder::Desc)) => query = query.order(id.desc()),
        (Some(SortBy::Id), _) => query = query.order(id.asc()),
        (Some(SortBy::Type), Some(SortOrder::Desc)) => query = query.order(type_.desc()),
        (Some(SortBy::Type), _) => query = query.order(type_.asc()),
        (Some(SortBy::Name), Some(SortOrder::Desc)) => query = query.order(name.desc()),
        (Some(SortBy::Name), _) => query = query.order(name.asc()),
        (None, _) => {}
    }

    if let Some(limit_val) = filter.limit {
        query = query.limit(limit_val as i64);
    }
    if let Some(offset_val) = filter.offset {
        query = query.offset(offset_val as i64);
    }

    query.select(models::Module::as_select()).load(conn)
}

pub async fn create_module(
    conn: &mut database::DbConnection,
    http_client: &reqwest::Client,
    s3_client: &aws_sdk_s3::Client,
    payload: &ModulePayload,
) -> Result<models::Module> {
    if get_module(conn, &payload.id).is_ok() {
        anyhow::bail!("Conflict: Module with ID '{}' already exists", payload.id);
    }

    let module_source = utils::source::Source::parse(&payload.file_url)?;
    let obj_key = format!("{}/module.wasm", payload.id);

    let body = match &module_source {
        utils::source::Source::Http(url) => {
            let response = utils::stream::stream_content_from_url(http_client, url)
                .await
                .context("Failed to fetch module file from URL")?;

            let stream = response.bytes_stream();
            let frames = stream.map_ok(hyper::body::Frame::data);
            let body = StreamBody::new(frames);
            byte_stream::ByteStream::from_body_1_x(body)
        }
        utils::source::Source::File(path) => utils::stream::stream_content_from_path(path)
            .await
            .context("Failed to read module file from path")?,
    };

    utils::s3::put_stream(s3_client, "modules", &obj_key, body, Some(&payload.digest))
        .await
        .context("Failed to upload module to S3")?;

    let new_module = models::NewModule {
        id: payload.id.clone(),
        type_: payload.r#type,
        name: payload.name.clone(),
        description: payload.description.clone(),
        digest: payload.digest.clone(),
        source_url: payload.source_url.clone(),
    };

    diesel::insert_into(schema::modules::table)
        .values(&new_module)
        .returning(models::Module::as_returning())
        .get_result(conn)
        .context("Failed to save module to database")
}

pub async fn create_module_from_registry(
    conn: &mut database::DbConnection,
    http_client: &reqwest::Client,
    s3_client: &aws_sdk_s3::Client,
    source_input: &str,
) -> Result<models::Module> {
    let source = utils::source::Source::parse(source_input)?;
    let mut payload = fetch_module(http_client, &source)
        .await
        .context("Failed to load module metadata")?;

    if payload.source_url.is_none() {
        payload.source_url = Some(source_input.to_string());
    }

    create_module(conn, http_client, s3_client, &payload).await
}

pub async fn update_module_from_source(
    conn: &mut database::DbConnection,
    http_client: &reqwest::Client,
    s3_client: &aws_sdk_s3::Client,
    module_id: &str,
) -> Result<models::Module> {
    let module =
        get_module(conn, module_id).context("Failed to fetch current module from database")?;
    let source_url_str = module
        .source_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Module does not have a source_url to update from"))?;
    let source = utils::source::Source::parse(source_url_str)?;
    let remote_payload = fetch_module(http_client, &source)
        .await
        .context("Failed to fetch updated module metadata from source")?;

    if module.digest == remote_payload.digest {
        return Ok(module);
    }

    let module_file_source = utils::source::Source::parse(&remote_payload.file_url)?;
    let obj_key = format!("{}/module.wasm", module.id);
    let body = match &module_file_source {
        utils::source::Source::Http(url) => {
            let response = utils::stream::stream_content_from_url(http_client, url)
                .await
                .context("Failed to fetch updated module file from URL")?;
            let stream = response.bytes_stream();
            let frames = stream.map_ok(hyper::body::Frame::data);
            let body = StreamBody::new(frames);

            byte_stream::ByteStream::from_body_1_x(body)
        }
        utils::source::Source::File(path) => utils::stream::stream_content_from_path(path)
            .await
            .context("Failed to read updated module file from path")?,
    };

    utils::s3::put_stream(
        s3_client,
        "modules",
        &obj_key,
        body,
        Some(&remote_payload.digest),
    )
    .await
    .context("Failed to upload updated module to S3")?;

    let update_data = models::UpdateModule {
        digest: Some(remote_payload.digest),
        ..Default::default()
    };

    db_update_module(conn, module_id, &update_data).context("Failed to update module in database")
}

#[cfg(test)]
#[path = "modules_tests.rs"]
mod tests;
