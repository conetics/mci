use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::{Request, Version};
use hyper_util::rt::tokio::TokioIo;
use mci::{app, config::Config, db, AppState};
use std::net::SocketAddr;
use tokio::net::TcpStream;

mod db_test_utils;

async fn spawn_app() -> SocketAddr {
    let config = Config {
        address: "127.0.0.1:0".to_string(),
        log_level: "info".to_string(),
        database_url: "postgres://postgres:postgres@localhost:5432/mci".to_string(),
        key_path: None,
        cert_path: None,
    };
    let db_pool = db::create_pool(&config.database_url);
    let app_state = AppState {
        db_pool: db_pool.clone(),
    };
    let app = app(app_state);
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

#[tokio::test]
async fn test_http1() {
    db_test_utils::setup_test_db().await;
    let addr = spawn_app().await;
    let stream = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await.unwrap();

    tokio::spawn(conn);

    let request = Request::builder()
        .version(Version::HTTP_11)
        .uri(format!("http://{}/test", addr))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();

    assert!(response.status().is_success());
    db_test_utils::teardown_test_db().await;
}

#[tokio::test]
async fn test_http2() {
    db_test_utils::setup_test_db().await;
    let addr = spawn_app().await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut client, h2) = h2::client::handshake(stream).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = h2.await {
            println!("GOT ERR: {:?}", e);
        }
    });

    let request = Request::builder()
        .version(Version::HTTP_2)
        .uri(format!("http://{}/test", addr))
        .body(())
        .unwrap();
    let (response_future, _) = client.send_request(request, true).unwrap();
    let response = response_future.await.unwrap();

    assert!(response.status().is_success());
    db_test_utils::teardown_test_db().await;
}
