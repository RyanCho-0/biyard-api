use std::{str::FromStr, time::SystemTime};

use crate::axum::{
    body::Body,
    extract::Request,
    http::{
        header::{AUTHORIZATION, COOKIE},
        Response, StatusCode,
    },
    middleware::Next,
};
use by_types::{AuthConfig, Claims};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rest_api::Signature;

static mut AUTH_CONFIG: Option<AuthConfig> = None;

pub fn set_auth_config(secret: AuthConfig) {
    unsafe {
        AUTH_CONFIG = Some(secret);
    }
}

pub fn get_auth_config() -> &'static AuthConfig {
    #[allow(static_mut_refs)]
    unsafe {
        AUTH_CONFIG
            .as_ref()
            .expect("you must call `set_auth_config` when starting a server")
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Authorization enum
///
/// # Variants
///
/// * `UserSig(Signature)` - User signature
/// * `Bearer(String)` - Bearer token
/// * `Basic` - Basic authentication
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Authorization {
    UserSig(Signature),
    Bearer { claims: Claims },
    Basic { username: String, password: String },
    ServerKey,
    SecretApiKey,
}

/// Authorization middleware
///
/// # Arguments
///
/// * `req` - The request
/// * `next` - The next middleware
///
/// # Returns
///
/// * `Response<Body>` - The response
/// * `StatusCode` - The status code of the response
pub async fn authorization_middleware(
    mut req: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    tracing::debug!("Authorization middleware {:?}", req.uri());
    let mut scheme: Option<&str> = None;
    let mut value: Option<&str> = None;

    if let Some(auth_header) = req.headers().get(COOKIE) {
        if let Ok(cookie_value) = auth_header.to_str() {
            let mut auth_value = cookie_value.split(';');
            let (sch, v) = auth_value
                .next()
                .unwrap_or_default()
                .split_once('=')
                .unwrap_or_default();
            scheme = Some(sch);
            value = Some(v);
        }
    }

    if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
        if let Ok(auth_value) = auth_header.to_str() {
            let mut auth_value = auth_value.split_whitespace();
            let (sch, v) = (auth_value.next(), auth_value.next());
            scheme = sch;
            value = v;
        }
    }
    tracing::debug!("Authorization Scheme: {:?}, Value {:?}", scheme, value);
    let ext = match scheme.unwrap_or_default().to_lowercase().as_str() {
        "usersig" => {
            tracing::debug!("User signature");
            verify_usersig(value).ok()
        }
        "bearer" => {
            tracing::debug!("Bearer token");
            verify_jwt(value).ok()
        }
        "secret" => {
            if option_env!("ENV").unwrap_or("local") == "prod" {
                None
            } else {
                verify_secret(value).ok()
            }
        }
        "x-server-key" => {
            tracing::debug!("server key");
            verify_server_key(value).ok()
        }
        _ => {
            tracing::debug!("Unknown scheme: {}", scheme.unwrap_or_default());
            None
        }
    };
    tracing::debug!("Authorization ext: {:?}", ext);
    if (ext.is_none()) {
        tracing::debug!("No Authorization header");
    }
    req.extensions_mut().insert(ext);
    Ok(next.run(req).await)
}

pub fn verify_server_key(value: Option<&str>) -> Result<Authorization, StatusCode> {
    if value.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let server_key = value.unwrap();
    let server_server_key = option_env!("SERVER_KEY")
        .expect("You must set SERVER_KEY to enable `server key` authentication");

    if server_key == server_server_key {
        return Ok(Authorization::ServerKey);
    }

    Err(StatusCode::UNAUTHORIZED)
}

pub fn verify_secret(value: Option<&str>) -> Result<Authorization, StatusCode> {
    if value.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let api_key = value.unwrap();
    let secret_server_key = option_env!("AUTH_SECRET_KEY")
        .expect("You must set AUTH_SECRET_KEY to enable `secret` authentication");

    if api_key == secret_server_key {
        return Ok(Authorization::SecretApiKey);
    }

    Err(StatusCode::UNAUTHORIZED)
}

pub fn generate_jwt(claims: &mut Claims) -> Result<String, StatusCode> {
    match get_auth_config() {
        &AuthConfig::Jwt {
            ref expiration,
            ref secret,
        } => {
            let exp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|e| {
                    tracing::error!("Failed to get current time: {}", e);
                    StatusCode::UNAUTHORIZED
                })?
                .as_secs()
                + expiration;
            claims.exp = exp;
            let token = match jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                claims,
                &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()),
            ) {
                Ok(token) => token,
                Err(err) => {
                    tracing::error!("Error creating JWT: {}", err);
                    return Err(StatusCode::UNAUTHORIZED);
                }
            };

            Ok(token)
        }
    }
}

pub fn verify_jwt(value: Option<&str>) -> Result<Authorization, StatusCode> {
    match get_auth_config() {
        AuthConfig::Jwt { secret, .. } => {
            if let Some(token) = value {
                let claims: Claims = jsonwebtoken::decode(
                    token,
                    &DecodingKey::from_secret(secret.as_ref()),
                    &Validation::new(Algorithm::HS256),
                )
                .map_err(|e| {
                    tracing::error!("Failed to decode token: {}", e);
                    StatusCode::UNAUTHORIZED
                })?
                .claims;

                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|e| {
                        tracing::error!("Failed to get current time: {}", e);
                        StatusCode::UNAUTHORIZED
                    })?
                    .as_secs();

                if now > claims.exp {
                    return Err(StatusCode::UNAUTHORIZED);
                }

                return Ok(Authorization::Bearer { claims });
            } else {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }
}

/// Verify the user signature
/// You must set the `DOMAIN` environment.
/// The signature is valid for 1 hour.
/// The signature is in the format of `timestamp:signature` for authorization header.
/// The signature is verified using the message `domain-timestamp` and the public key of the user.
///
/// # Arguments
///
/// * `value` - The value of the Authorization header
///
/// # Returns
///
/// * `Signature` - The signature of the user
/// * `StatusCode` - The status code of the response
pub fn verify_usersig(value: Option<&str>) -> Result<Authorization, StatusCode> {
    if let Some((timestamp, signature)) = value.unwrap_or_default().split_once(":") {
        let parsed_timestamp: i64 = timestamp.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;
        if now() - parsed_timestamp >= 3600 {
            tracing::error!("Expired timestamp: {}", timestamp);
            return Err(StatusCode::UNAUTHORIZED);
        }

        let msg = format!(
            "{}-{}",
            option_env!("AUTH_DOMAIN").expect("You must set AUTH_DOMAIN environment"),
            timestamp
        );
        let sig = rest_api::Signature::from_str(signature).map_err(|e| {
            tracing::error!("Failed to parse signature: {}", e);
            StatusCode::UNAUTHORIZED
        })?;
        tracing::debug!("SignMessage: {}", msg);
        let address = sig.verify(&msg).map_err(|e| {
            tracing::error!("Failed to verify signature: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

        if address.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        return Ok(Authorization::UserSig(sig));
    }

    Err(StatusCode::UNAUTHORIZED)
}
