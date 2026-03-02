mod common;

use anyhow::Result;
use diesel::prelude::*;
use mci::{
    models::{Module, ModuleType, NewModule},
    schema::modules::dsl::*,
    services::modules::{
        create_module, create_module_from_registry, list_modules, update_module,
        update_module_from_source, ModuleFilter, ModulePayload, SortBy, SortOrder,
    },
};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use common::{initialize_pg, initialize_s3};

#[tokio::test]
async fn create_module_from_http_source() -> Result<()> {
    let (pg_container, pool) = initialize_pg().await?;
    let (s3_container, s3_client) = initialize_s3().await?;

    s3_client.create_bucket().bucket("modules").send().await?;

    let mock = MockServer::start().await;
    let wasm_body = b"hello-mod";
    let digest_str = format!("sha256:{:x}", Sha256::digest(wasm_body));

    Mock::given(method("GET"))
        .and(path("/module.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(wasm_body, "application/wasm"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/meta.json"))
        .and(header("User-Agent", "MCI/1.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ModulePayload {
            id: "mod-1".into(),
            name: "Example Name".into(),
            r#type: ModuleType::Sandbox,
            description: "Example description".into(),
            file_url: format!("{}/module.wasm", mock.uri()),
            digest: digest_str.clone(),
            source_url: Some(format!("{}/meta.json", mock.uri())),
        }))
        .mount(&mock)
        .await;

    let digest_for_task = digest_str.clone();

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        let http_client = reqwest::Client::new();
        let s3_client = s3_client.clone();
        let meta_url = format!("{}/meta.json", mock.uri());

        move || -> Result<Module> {
            let mut conn = pool.get()?;
            let payload = ModulePayload {
                id: "mod-1".into(),
                name: "Example Name".into(),
                r#type: ModuleType::Proxy,
                description: "Example description".into(),
                file_url: format!("{}/module.wasm", mock.uri()),
                digest: digest_for_task,
                source_url: Some(meta_url.clone()),
            };

            let result: Result<Module> = tokio::runtime::Handle::current().block_on(async {
                create_module(&mut conn, &http_client, &s3_client, &payload).await
            });
            result
        }
    })
    .await??;

    let inserted = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<Module> {
            let mut conn = pool.get()?;
            modules.find("mod-1").first(&mut conn).map_err(Into::into)
        }
    })
    .await??;

    assert_eq!(inserted.digest, digest_str);
    assert_eq!(inserted.name, "Example Name");

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn create_module_conflict_errors() -> Result<()> {
    let (pg_container, pool) = initialize_pg().await?;
    let (s3_container, s3_client) = initialize_s3().await?;

    s3_client.create_bucket().bucket("modules").send().await?;

    let mock = MockServer::start().await;
    let mock_uri = mock.uri();

    let wasm_body = b"hello-conflict";
    let digest_str = format!("sha256:{:x}", Sha256::digest(wasm_body));

    Mock::given(method("GET"))
        .and(path("/module.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(wasm_body, "application/wasm"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/meta.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ModulePayload {
            id: "mod-2".into(),
            name: "Name".into(),
            r#type: ModuleType::Hook,
            description: "d".into(),
            file_url: format!("{}/module.wasm", mock_uri.clone()),
            digest: digest_str.clone(),
            source_url: Some(format!("{}/meta.json", mock_uri.clone())),
        }))
        .mount(&mock)
        .await;

    let http_client = reqwest::Client::new();

    let file_url = format!("{}/module.wasm", mock_uri.clone());
    let meta_url = format!("{}/meta.json", mock_uri.clone());

    let digest_for_task = digest_str.clone();

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        let s3_client = s3_client.clone();
        let http_client = http_client.clone();

        move || -> Result<()> {
            let mut conn = pool.get()?;
            let payload = ModulePayload {
                id: "mod-2".into(),
                name: "Name".into(),
                r#type: ModuleType::Language,
                description: "d".into(),
                file_url: file_url.clone(),
                digest: digest_for_task.clone(),
                source_url: None,
            };
            let result: Result<Module> = tokio::runtime::Handle::current().block_on(async {
                create_module(&mut conn, &http_client, &s3_client, &payload).await
            });
            result.map(|_| ())
        }
    })
    .await??;

    let digest_for_task = digest_str.clone();

    let conflict_result = tokio::task::spawn_blocking({
        let pool = pool.clone();
        let s3_client = s3_client.clone();
        let http_client = http_client.clone();

        let file_url = format!("{}/file.json", mock_uri.clone());
        let meta_url = meta_url.clone();

        move || -> Result<()> {
            let mut conn = pool.get()?;
            let payload = ModulePayload {
                id: "mod-2".into(),
                name: "Name".into(),
                r#type: ModuleType::Proxy,
                description: "d".into(),
                file_url,
                digest: digest_for_task,
                source_url: Some(meta_url),
            };
            let result: Result<Module> = tokio::runtime::Handle::current().block_on(async {
                create_module(&mut conn, &http_client, &s3_client, &payload).await
            });
            result?;
            Ok(())
        }
    })
    .await?;

    assert!(conflict_result.is_err());

    let err = conflict_result.unwrap_err();

    assert!(err.to_string().contains("Conflict: Module with ID 'mod-2'"));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn create_module_from_registry_sets_source_url() -> Result<()> {
    let (pg_container, pool) = initialize_pg().await?;
    let (s3_container, s3_client) = initialize_s3().await?;

    s3_client.create_bucket().bucket("modules").send().await?;

    let mock = MockServer::start().await;
    let wasm_body = b"registry-body";
    let digest_str = format!("sha256:{:x}", Sha256::digest(wasm_body));
    let registry_url = format!("{}/registry.json", mock.uri());

    Mock::given(method("GET"))
        .and(path("/module.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(wasm_body, "application/wasm"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ModulePayload {
            id: "mod-3".into(),
            name: "RegName".into(),
            r#type: ModuleType::Sandbox,
            description: "reg-desc".into(),
            file_url: format!("{}/module.wasm", mock.uri()),
            digest: digest_str.clone(),
            source_url: None,
        }))
        .mount(&mock)
        .await;

    let http_client = reqwest::Client::new();

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        let http_client = http_client.clone();
        let s3_client = s3_client.clone();
        let registry_url = registry_url.clone();

        move || -> Result<Module> {
            let mut conn = pool.get()?;
            let result: Result<Module> = tokio::runtime::Handle::current().block_on(async {
                create_module_from_registry(&mut conn, &http_client, &s3_client, &registry_url)
                    .await
            });
            result
        }
    })
    .await??;

    let row = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<Module> {
            let mut conn = pool.get()?;
            modules.find("mod-3").first(&mut conn).map_err(Into::into)
        }
    })
    .await??;

    assert_eq!(row.source_url.as_deref(), Some(registry_url.as_str()));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn update_module_from_source_updates_when_digest_changes() -> Result<()> {
    let (pg_container, pool) = initialize_pg().await?;
    let (s3_container, s3_client) = initialize_s3().await?;

    s3_client.create_bucket().bucket("modules").send().await?;

    let mock = MockServer::start().await;

    let old_wasm = b"old-body";
    let old_digest = format!("sha256:{:x}", Sha256::digest(old_wasm));

    let new_wasm = b"new-body";
    let new_digest = format!("sha256:{:x}", Sha256::digest(new_wasm));

    Mock::given(method("GET"))
        .and(path("/module-new.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(new_wasm, "application/wasm"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/meta.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ModulePayload {
            id: "mod-4".into(),
            name: "New Name".into(),
            r#type: ModuleType::Interceptor,
            description: "New Desc".into(),
            file_url: format!("{}/module-new.wasm", mock.uri()),
            digest: new_digest.clone(),
            source_url: Some(format!("{}/meta.json", mock.uri())),
        }))
        .mount(&mock)
        .await;

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        let old_digest = old_digest.clone();

        move || -> Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(modules)
                .values(&NewModule {
                    id: "mod-4".into(),
                    type_: ModuleType::Proxy,
                    name: "Old Name".into(),
                    description: "Old Desc".into(),
                    digest: old_digest,
                    source_url: Some(format!("{}/meta.json", mock.uri())),
                })
                .execute(&mut conn)?;
            Ok(())
        }
    })
    .await??;

    let http_client = reqwest::Client::new();

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        let http_client = http_client.clone();
        let s3_client = s3_client.clone();

        move || -> Result<Module> {
            let mut conn = pool.get()?;
            let result: Result<Module> = tokio::runtime::Handle::current().block_on(async {
                update_module_from_source(&mut conn, &http_client, &s3_client, "mod-4").await
            });
            result
        }
    })
    .await??;

    let updated = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<Module> {
            let mut conn = pool.get()?;
            modules.find("mod-4").first(&mut conn).map_err(Into::into)
        }
    })
    .await??;

    assert_eq!(updated.digest, new_digest);
    assert_eq!(updated.name, "Old Name");
    assert_eq!(updated.description, "Old Desc");
    assert_eq!(updated.type_, ModuleType::Proxy);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn update_module_via_request_strips_digest() -> Result<()> {
    use mci::models::UpdateModuleRequest;

    let (pg_container, pool) = initialize_pg().await?;

    let old_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(modules)
                .values(&NewModule {
                    id: "mod-update-digest".into(),
                    type_: ModuleType::Proxy,
                    name: "Old Name".into(),
                    description: "Old Desc".into(),
                    digest: old_digest.into(),
                    source_url: Some("http://example.com/mod.json".into()),
                })
                .execute(&mut conn)?;
            Ok(())
        }
    })
    .await??;

    let request = UpdateModuleRequest {
        is_enabled: None,
        name: Some("New Name".into()),
        description: None,
        source_url: None,
    };
    let update = request.into_changeset();

    assert_eq!(update.digest, None);

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<()> {
            let mut conn = pool.get()?;
            update_module(&mut conn, "mod-update-digest", &update)?;
            Ok(())
        }
    })
    .await??;

    let updated = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<Module> {
            let mut conn = pool.get()?;
            modules
                .find("mod-update-digest")
                .first(&mut conn)
                .map_err(Into::into)
        }
    })
    .await??;

    assert_eq!(updated.name, "New Name");
    assert_eq!(updated.digest, old_digest);

    pg_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn list_modules_filters_and_sorting() -> Result<()> {
    let (pg_container, pool) = initialize_pg().await?;

    tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<()> {
            let mut conn = pool.get()?;
            diesel::insert_into(modules)
                .values(&vec![
                    NewModule {
                        id: "a1".into(),
                        type_: ModuleType::Proxy,
                        name: "Alpha".into(),
                        description: "First".into(),
                        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                        source_url: None,
                    },
                    NewModule {
                        id: "b2".into(),
                        type_: ModuleType::Sandbox,
                        name: "Beta".into(),
                        description: "Second".into(),
                        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                        source_url: None,
                    },
                    NewModule {
                        id: "c3".into(),
                        type_: ModuleType::Proxy,
                        name: "Gamma".into(),
                        description: "Third".into(),
                        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                        source_url: None,
                    },
                ])
                .execute(&mut conn)?;

            diesel::update(modules)
                .set(is_enabled.eq(true))
                .execute(&mut conn)?;
            diesel::update(modules.find("b2"))
                .set(is_enabled.eq(false))
                .execute(&mut conn)?;

            Ok(())
        }
    })
    .await??;

    let by_query = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<Vec<Module>> {
            let mut conn = pool.get()?;
            list_modules(
                &mut conn,
                &ModuleFilter {
                    query: Some("amm".into()),
                    ..Default::default()
                },
            )
            .map_err(Into::into)
        }
    })
    .await??;

    assert_eq!(by_query.len(), 1);
    assert_eq!(by_query[0].id, "c3");

    let disabled = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<Vec<Module>> {
            let mut conn = pool.get()?;
            list_modules(
                &mut conn,
                &ModuleFilter {
                    is_enabled: Some(false),
                    ..Default::default()
                },
            )
            .map_err(Into::into)
        }
    })
    .await??;

    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].id, "b2");

    let sorted = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || -> Result<Vec<Module>> {
            let mut conn = pool.get()?;
            list_modules(
                &mut conn,
                &ModuleFilter {
                    r#type: Some(ModuleType::Proxy),
                    sort_by: Some(SortBy::Name),
                    sort_order: Some(SortOrder::Desc),
                    ..Default::default()
                },
            )
            .map_err(Into::into)
        }
    })
    .await??;

    let ids: Vec<_> = sorted.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, vec!["c3", "a1"]);

    pg_container.stop().await.ok();

    Ok(())
}
