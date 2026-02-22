use anyhow::Result;
use aws_smithy_types::byte_stream::ByteStream;
use mci::utils::s3_utils;
use uuid::Uuid;

mod common;

#[tokio::test]
async fn delete_objects_with_prefix_removes_objects() -> Result<()> {
    let (container, client) = common::initialize_s3().await?;
    let bucket = format!("test-bucket-{}", Uuid::new_v4());
    client.create_bucket().bucket(&bucket).send().await?;

    let prefix = "test-prefix/";
    let keys = [
        format!("{}a.txt", prefix),
        format!("{}b.txt", prefix),
        format!("{}subdir/c.txt", prefix),
    ];
    for key in &keys {
        client
            .put_object()
            .bucket(&bucket)
            .key(key)
            .body(ByteStream::from_static(b"to be deleted"))
            .send()
            .await?;
    }

    let listed = client
        .list_objects_v2()
        .bucket(&bucket)
        .prefix(prefix)
        .send()
        .await?;
    assert_eq!(listed.key_count(), Some(keys.len() as i32));

    s3_utils::delete_objects_with_prefix(&client, &bucket, prefix).await?;

    let listed = client
        .list_objects_v2()
        .bucket(&bucket)
        .prefix(prefix)
        .send()
        .await?;
    assert_eq!(listed.key_count(), Some(0));

    container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn delete_objects_with_prefix_empty_prefix_ok() -> Result<()> {
    let (container, client) = common::initialize_s3().await?;
    let bucket = format!("test-bucket-{}", Uuid::new_v4());
    client.create_bucket().bucket(&bucket).send().await?;

    s3_utils::delete_objects_with_prefix(&client, &bucket, "empty-prefix/").await?;

    container.stop().await.ok();
    Ok(())
}
