pub mod auth;
pub mod axum;
mod docs;
use std::sync::Arc;

use ::axum::{Extension, Json, Router};
use http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    Method,
};
pub use logger as log;
use router::BiyardRouter;

#[cfg(feature = "lambda")]
pub mod lambda_adapter;
pub mod logger;
pub mod router;
pub use aide;
pub mod rest_api_adapter;

pub use by_types::ApiError;
pub type Result<T, E> = std::result::Result<Json<T>, ApiError<E>>;
pub use schemars;
use tower_http::cors::AllowOrigin;

pub fn new() -> BiyardRouter {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .try_init();

    BiyardRouter::new()
}

pub fn finishing(app: BiyardRouter) -> Router {
    let mut api = app.open_api;
    app.inner
        .finish_api(&mut api)
        .layer(Extension(Arc::new(api)))
}

pub fn with_cors(app: BiyardRouter)
pub async fn serve(
    _tcp_listener: tokio::net::TcpListener,
    app: BiyardRouter,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // FIXME: Add CORS Layer Outer-side
    // The current CORS configuration is hardcoded within the by_axum package, making it difficult to control flexibly from the outside.
    // the CORS Layer needs to be configurable from outside the by_axum package.

    let app = app.layer(
        tower_http::cors::CorsLayer::new()
            .allow_origin(AllowOrigin::exact("http://127.0.0.1:8080".parse().unwrap()))
            .allow_credentials(true)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(vec![CONTENT_TYPE, AUTHORIZATION]),
    );
    let mut api = app.open_api;
    let app = app
        .inner
        .finish_api(&mut api)
        .layer(Extension(Arc::new(api)));

    #[cfg(not(feature = "lambda"))]
    axum::serve(_tcp_listener, app).await?;

    #[cfg(feature = "lambda")]
    {
        lambda_runtime::run(lambda_adapter::LambdaAdapter::from(app.into_service()))
            .await
            .unwrap();
    }

    Ok(())
}

pub fn into_api_adapter(app: BiyardRouter) -> rest_api_adapter::RestApiAdapter {
    let app = finishing(app);
    rest_api_adapter::RestApiAdapter::new(app)
}
