 #!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# === SPeCK LLM Bridge – Max OPSEC Installer ===
# Usage: bash install-bridge.sh
# After install, copy the shown key into SPCK.

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}▶ Installing SPeCK LLM Bridge (hardened)${NC}"

# 1. System dependencies
pkg update -y
pkg install -y curl clang openssl-tool

# 2. Install rustup (official)
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    source "$HOME/.cargo/env"
    echo 'source "$HOME/.cargo/env"' >> ~/.bashrc
fi

# 3. Add Android target and configure linker
rustup target add aarch64-linux-android
mkdir -p ~/.cargo
cat > ~/.cargo/config.toml << 'EOF'
[target.aarch64-linux-android]
linker = "clang"
rustflags = ["-C", "target-cpu=native", "-C", "link-arg=-z", "-C", "link-arg=now", "-C", "link-arg=-z", "-C", "link-arg=relro"]
EOF

# 4. Create project directory
PROJECT="$HOME/spck-llm-bridge"
mkdir -p "$PROJECT/src"
cd "$PROJECT"

# 5. Write Cargo.toml (hardened)
cat > Cargo.toml << 'EOF'
[package]
name = "spck-llm-bridge"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["rt", "net", "macros", "signal"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["trace", "limit"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }
http-body-util = "0.1"
bytes = "1"
anyhow = "1"
clap = { version = "4", features = ["derive"] }
sha2 = "0.10"
subtle = "2.5"
once_cell = "1"

[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "abort"
overflow-checks = true
EOF

# 6. Write config.rs
cat > src/config.rs << 'EOF'
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::{bail, Context};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub bind: String,
    pub backend_url: String,
    pub auth_key_hash: String,
    pub max_body_kb: usize,
    pub log_redact_content: bool,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut cfg: Config = toml::from_str(&contents)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let host = self.bind.split(':').next().unwrap_or("");
        if host != "127.0.0.1" && host != "localhost" {
            bail!("Bind must be loopback (127.0.0.1/localhost)");
        }
        if self.max_body_kb == 0 || self.max_body_kb > 1024 {
            bail!("max_body_kb 1..1024");
        }
        Ok(())
    }
}
EOF

# 7. Write auth.rs (constant‑time)
cat > src/auth.rs << 'EOF'
use subtle::ConstantTimeEq;
use sha2::{Sha256, Digest};
use axum::{http::{Request, StatusCode}, middleware::Next, response::Response};
use tracing::warn;
use once_cell::sync::OnceCell;
use crate::config::Config;

pub static CONFIG: OnceCell<Config> = OnceCell::new();

pub async fn auth_middleware<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let cfg = CONFIG.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let key = req.headers().get("X-Bridge-Key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let hash = hex::encode(Sha256::digest(key.as_bytes()));
    let expected = cfg.auth_key_hash.as_bytes();
    let provided = hash.as_bytes();
    if bool::from(expected.ct_eq(provided)) {
        Ok(next.run(req).await)
    } else {
        warn!("Auth failed (timing-safe)");
        Err(StatusCode::UNAUTHORIZED)
    }
}
EOF

# 8. Write proxy.rs
cat > src/proxy.rs << 'EOF'
use axum::{extract::State, http::{Method, StatusCode}, response::{IntoResponse, Response}};
use bytes::Bytes;
use std::sync::Arc;
use tracing::{info, warn};

pub struct AppState {
    pub client: reqwest::Client,
    pub backend_url: String,
    pub log_redact: bool,
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    path: String,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let url = format!("{}{}", state.backend_url, path);
    let mut req = state.client.request(method, &url);
    for (name, value) in headers.iter() {
        let name = name.as_str();
        if !matches!(name, "host" | "connection" | "content-length" | "x-bridge-key") {
            req = req.header(name, value);
        }
    }
    match req.body(body).send().await {
        Ok(resp) => {
            let status = resp.status();
            let mut builder = Response::builder().status(status);
            for (k, v) in resp.headers() {
                builder = builder.header(k, v);
            }
            let bytes = resp.bytes().await.unwrap_or_default();
            if state.log_redact && !bytes.is_empty() {
                info!("Response (redacted): {} bytes", bytes.len());
            }
            builder.body(bytes.into()).unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(e) => {
            warn!("Proxy error: {}", e);
            (StatusCode::BAD_GATEWAY, e.to_string()).into_response()
        }
    }
}
EOF

# 9. Write main.rs
cat > src/main.rs << 'EOF'
mod config;
mod auth;
mod proxy;

use axum::{Router, middleware, routing::{any, post, get}};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, sync::Arc};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use crate::config::Config;
use crate::auth::auth_middleware;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve { config: String },
    HashKey { key: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("spck_llm_bridge=info")
        .with_span_events(FmtSpan::CLOSE)
        .json()
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Serve { config } => {
            let cfg = Config::from_file(&std::path::PathBuf::from(&config))?;
            auth::CONFIG.set(cfg.clone()).unwrap();
            let state = Arc::new(proxy::AppState {
                client: reqwest::Client::builder()
                    .use_rustls_tls()
                    .build()?,
                backend_url: cfg.backend_url,
                log_redact: cfg.log_redact_content,
            });
            let app = Router::new()
                .route("/v1/chat/completions", post(proxy::proxy_handler))
                .route("/v1/completions", post(proxy::proxy_handler))
                .route("/api/generate", post(proxy::proxy_handler))
                .route("/api/tags", get(proxy::proxy_handler))
                .route("/*path", any(proxy::proxy_handler))
                .layer(middleware::from_fn(auth_middleware))
                .layer(RequestBodyLimitLayer::new(cfg.max_body_kb * 1024))
                .with_state(state);
            let addr: SocketAddr = cfg.bind.parse()?;
            info!("Listening on http://{}", addr);
            axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
        }
        Commands::HashKey { key } => {
            let hash = hex::encode(sha2::Sha256::digest(key.as_bytes()));
            println!("{}", hash);
        }
    }
    Ok(())
}
EOF

# 10. Build release binary
echo -e "${GREEN}▶ Building hardened binary (first time: 2‑4 min)${NC}"
cargo build --release

# 11. Generate random key (display only once)
RANDOM_KEY=$(openssl rand -hex 32)
HASH=$(./target/release/spck-llm-bridge hash-key "$RANDOM_KEY")
mkdir -p "$HOME/.config/spck-bridge"
CONFIG_FILE="$HOME/.config/spck-bridge/config.toml"
cat > "$CONFIG_FILE" <<EOF
bind = "127.0.0.1:3030"
backend_url = "http://127.0.0.1:11434"
auth_key_hash = "$HASH"
max_body_kb = 512
log_redact_content = true
EOF
chmod 600 "$CONFIG_FILE"

# 12. Generate SPCK plugin with key embedded
PLUGIN_FILE="$PROJECT/plugin.js"
cat > "$PLUGIN_FILE" <<EOF
// === SPeCK LLM Bridge Plugin (OPSEC hardened) ===
// Paste into SPCK JS console, then run: LLM.setKey()
window.LLM = (() => {
    let key = null;
    const url = 'http://127.0.0.1:3030';
    const setKey = (k) => { key = k; };
    const call = async (endpoint, body) => {
        if (!key) throw new Error('Call LLM.setKey("$RANDOM_KEY") first');
        const r = await fetch(url + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Bridge-Key': key },
            body: JSON.stringify(body)
        });
        if (!r.ok) throw new Error(await r.text());
        return r.json();
    };
    const complete = (prompt, model='llama3') => call('/v1/completions', { model, prompt });
    const chat = (messages, model='llama3') => call('/v1/chat/completions', { model, messages });
    const generate = (prompt, model='llama3') => call('/api/generate', { model, prompt }).then(j => j.response);
    const review = async () => {
        const editor = monaco?.editor?.getModels()[0]?.getEditor?.() || document.querySelector('.monaco-editor')?.__editor;
        if (!editor) throw new Error('No Monaco editor');
        const code = editor.getValue();
        return await generate(\`Code review:\n\` + code);
    };
    return { setKey, complete, chat, generate, review };
})();
// Set your key:
LLM.setKey("$RANDOM_KEY");
EOF

echo -e "${GREEN}✅ Installation complete!${NC}"
echo "────────────────────────────────────────────"
echo -e "${GREEN}🔑 YOUR SECRET KEY (store safely):${NC} $RANDOM_KEY"
echo -e "${GREEN}📁 Config:${NC} $CONFIG_FILE"
echo -e "${GREEN}📜 Plugin:${NC} $PLUGIN_FILE"
echo ""
echo "To start the bridge:"
echo "  cd $PROJECT && RUST_LOG=info ./target/release/spck-llm-bridge serve --config $CONFIG_FILE"
echo ""
echo "Make sure Ollama is running:"
echo "  ollama serve &"
echo "  ollama pull tinyllama"
echo ""
echo "In SPCK, paste the contents of $PLUGIN_FILE into the JS console."
echo "────────────────────────────────────────────"
