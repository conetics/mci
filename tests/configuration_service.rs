mod common;

use anyhow::Result;
use aws_smithy_types::byte_stream::ByteStream;
use mci::services::configuration::{self, ConfigurationTarget};
use serde_json::json;
use common::initialize_s3;

async fn create_configuration_buckets(client: &aws_sdk_s3::Client) -> Result<()> {
    client
        .create_bucket()
        .bucket("definition-configurations")
        .send()
        .await?;
    client
        .create_bucket()
        .bucket("module-configurations")
        .send()
        .await?;

    Ok(())
}

#[tokio::test]
async fn get_schema_and_configuration_reads_from_target_bucket() -> Result<()> {
    let (container, client) = initialize_s3().await?;
    create_configuration_buckets(&client).await?;

    let id = "definition-a";
    let schema = json!({
        "type": "object",
        "properties": {
            "enabled": { "type": "boolean" }
        },
        "required": ["enabled"],
        "additionalProperties": false
    });
    let config = json!({ "enabled": true });

    client
        .put_object()
        .bucket("definition-configurations")
        .key(format!("{}/configuration.schema.json", id))
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    client
        .put_object()
        .bucket("definition-configurations")
        .key(format!("{}/configuration.json", id))
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let loaded_schema =
        configuration::get_schema(&client, ConfigurationTarget::Definition, id).await?;
    let loaded_config =
        configuration::get_configuration(&client, ConfigurationTarget::Definition, id)
            .await?;

    assert_eq!(loaded_schema, schema);
    assert_eq!(loaded_config, config);

    container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn put_configuration_validates_and_persists() -> Result<()> {
    let (container, client) = initialize_s3().await?;
    create_configuration_buckets(&client).await?;

    let id = "module-a";
    let schema = json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "enabled": { "type": "boolean" }
        },
        "required": ["name", "enabled"],
        "additionalProperties": false
    });

    client
        .put_object()
        .bucket("module-configurations")
        .key(format!("{}/configuration.schema.json", id))
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let config = json!({
        "name": "module-a",
        "enabled": true
    });

    configuration::put_configuration(&client, ConfigurationTarget::Module, id, &config)
        .await?;

    let loaded =
        configuration::get_configuration(&client, ConfigurationTarget::Module, id).await?;
    assert_eq!(loaded, config);

    container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn put_configuration_rejects_invalid_input() -> Result<()> {
    let (container, client) = initialize_s3().await?;
    create_configuration_buckets(&client).await?;

    let id = "module-b";
    let schema = json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "enabled": { "type": "boolean" }
        },
        "required": ["name", "enabled"],
        "additionalProperties": false
    });

    client
        .put_object()
        .bucket("module-configurations")
        .key(format!("{}/configuration.schema.json", id))
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let invalid_config = json!({
        "name": 123,
        "enabled": "yes"
    });

    let result = configuration::put_configuration(
        &client,
        ConfigurationTarget::Module,
        id,
        &invalid_config,
    )
    .await;

    assert!(result.is_err());

    let loaded =
        configuration::get_configuration(&client, ConfigurationTarget::Module, id).await;
    assert!(loaded.is_err(), "invalid config should not be stored");

    container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn delete_configuration_cleans_entire_prefix() -> Result<()> {
    let (container, client) = initialize_s3().await?;
    create_configuration_buckets(&client).await?;

    let id = "definition-to-clean";
    let keys = [
        format!("{}/configuration.json", id),
        format!("{}/configuration.schema.json", id),
        format!("{}/extra/notes.json", id),
    ];

    for key in keys {
        client
            .put_object()
            .bucket("definition-configurations")
            .key(&key)
            .body(ByteStream::from_static(b"{}"))
            .send()
            .await?;
    }

    client
        .put_object()
        .bucket("definition-configurations")
        .key("other-id/configuration.json")
        .body(ByteStream::from_static(b"{}"))
        .send()
        .await?;

    configuration::delete_configuration(&client, ConfigurationTarget::Definition, id)
        .await?;

    let deleted_prefix_listing = client
        .list_objects_v2()
        .bucket("definition-configurations")
        .prefix(format!("{}/", id))
        .send()
        .await?;
    assert_eq!(deleted_prefix_listing.key_count(), Some(0));

    let other_prefix_listing = client
        .list_objects_v2()
        .bucket("definition-configurations")
        .prefix("other-id/")
        .send()
        .await?;
    assert_eq!(other_prefix_listing.key_count(), Some(1));

    container.stop().await.ok();
    Ok(())
}
