#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# === SPeCK LLM Bridge – MAX OPSEC Hardened Installer ===
# Usage: bash install-bridge.sh
# After install, copy the shown key into your SPCK JS console.

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}▶ Installing SPeCK LLM Bridge (MAX OPSEC edition)${NC}"

# 1. System dependencies
echo -e "${YELLOW}→ Updating packages and installing build deps...${NC}"
pkg update -y
pkg install -y curl clang openssl-tool git make libclang

# 2. Install rustup (official, minimal)
if ! command -v rustc &>/dev/null; then
    echo -e "${YELLOW}→ Installing Rust (minimal profile)...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    source "$HOME/.cargo/env"
    echo 'source "$HOME/.cargo/env"' >> ~/.bashrc
fi
source "$HOME/.cargo/env"

# 3. Android target + hardened linker config
rustup target add aarch64-linux-android
mkdir -p ~/.cargo
cat > ~/.cargo/config.toml << 'EOF'
[target.aarch64-linux-android]
linker = "clang"
rustflags = [
    "-C", "target-cpu=native",
    "-C", "link-arg=-z", "-C", "link-arg=now",
    "-C", "link-arg=-z", "-C", "link-arg=relro",
    "-C", "link-arg=-z", "-C", "link-arg=nocopyreloc"
]
EOF

# 4. Project directory
PROJECT="$HOME/spck-llm-bridge"
mkdir -p "$PROJECT/src"
cd "$PROJECT"

# 5. Hardened Cargo.toml
cat > Cargo.toml << 'EOF'
[package]
name = "spck-llm-bridge"
version = "0.2.0"
edition = "2021"
authors = ["SPeCK User"]
license = "MIT OR Apache-2.0"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["rt-multi-thread", "net", "macros", "signal"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["trace", "limit", "cors"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
reqwest = { version = "0.12", features = ["json", "rustls-tls-native-roots"] }
http-body-util = "0.1"
bytes = "1"
anyhow = "1"
clap = { version = "4", features = ["derive"] }
sha2 = "0.10"
subtle = "2.5"
once_cell = "1"
hex = "0.4"

[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "abort"
overflow-checks = true
debug = false
EOF

# 6. Config
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
        let contents = std::fs::read_to_string(path).context("Failed to read config")?;
        let mut cfg: Config = toml::from_str(&contents)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let host = self.bind.split(':').next().unwrap_or("");
        if !matches!(host, "127.0.0.1" | "localhost") {
            bail!("Bind address must be loopback only (127.0.0.1 or localhost) for OPSEC");
        }
        if self.max_body_kb == 0 || self.max_body_kb > 1024 {
            bail!("max_body_kb must be between 1 and 1024");
        }
        if self.auth_key_hash.len() != 64 {
            bail!("auth_key_hash must be a valid SHA-256 hex string");
        }
        Ok(())
    }
}
EOF

# 7. Constant-time auth
# FIX: axum 0.7 dropped the <B> generic on Next — signature is now (Request, Next) -> Response
cat > src/auth.rs << 'EOF'
use subtle::ConstantTimeEq;
use sha2::{Sha256, Digest};
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use tracing::warn;
use once_cell::sync::OnceCell;
use crate::config::Config;

pub static CONFIG: OnceCell<Config> = OnceCell::new();

pub async fn auth_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    let cfg = CONFIG.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let key = req
        .headers()
        .get("X-Bridge-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let provided_hash = hex::encode(Sha256::digest(key.as_bytes()));
    let expected = cfg.auth_key_hash.as_bytes();

    if bool::from(expected.ct_eq(provided_hash.as_bytes())) {
        Ok(next.run(req).await)
    } else {
        warn!("Authentication failed (constant-time comparison)");
        Err(StatusCode::UNAUTHORIZED)
    }
}
EOF

# 8. Proxy handler
# FIX: Do NOT extract Path(path) from the route — named routes like /v1/chat/completions
# have no {path} segment so axum panics at extraction time. Use OriginalUri instead,
# which captures the full request URI regardless of which route matched.
cat > src/proxy.rs << 'EOF'
use axum::{
    extract::{OriginalUri, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
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
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let url = format!(
        "{}{}",
        state.backend_url.trim_end_matches('/'),
        path_and_query
    );

    let mut req = state.client.request(method, &url);

    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if !matches!(
            name_str.as_str(),
            "host" | "connection" | "content-length" | "x-bridge-key" | "upgrade"
        ) {
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
                info!("Proxied response: {} bytes (content redacted)", bytes.len());
            } else if !state.log_redact {
                info!("Proxied response: {} bytes", bytes.len());
            }

            builder
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(e) => {
            warn!("Proxy error to backend: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Backend error: {}", e)).into_response()
        }
    }
}
EOF

# 9. Main.rs
# FIX 1: Collapse all specific named routes + wildcard into a single "/*path" any() route.
#         The named routes were redundant (/*path catches everything) AND broken because
#         the handler uses OriginalUri now, not Path extraction.
# FIX 2: Clap Serve subcommand config field needs #[arg(long)] so --config flag works.
#         Previously it was positional, but start-bridge.sh called `serve --config <path>`.
cat > src/main.rs << 'EOF'
mod config;
mod auth;
mod proxy;

use axum::{Router, middleware, routing::any};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, sync::Arc};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use crate::auth::auth_middleware;

#[derive(Parser)]
#[command(name = "spck-llm-bridge", version, about = "Hardened LLM proxy bridge for SPCK/Termux")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy bridge
    Serve {
        /// Path to TOML config file
        #[arg(long, short = 'c')]
        config: String,
    },
    /// Print the SHA-256 hash of a key (for config generation)
    HashKey {
        /// The plaintext key to hash
        key: String,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("spck_llm_bridge=info,reqwest=warn")
        .with_span_events(FmtSpan::CLOSE)
        .json()
        .init();

    let cli = Cli::parse();

    match cli.cmd {
        Commands::Serve { config } => {
            let cfg = config::Config::from_file(&std::path::PathBuf::from(&config))?;
            auth::CONFIG.set(cfg.clone()).expect("Failed to set global config");

            let state = Arc::new(proxy::AppState {
                client: reqwest::Client::builder()
                    .use_rustls_tls()
                    .timeout(std::time::Duration::from_secs(120))
                    .build()?,
                backend_url: cfg.backend_url.clone(),
                log_redact: cfg.log_redact_content,
            });

            let app = Router::new()
                // Single wildcard route — OriginalUri in handler preserves the full path.
                // More specific routes would be redundant and caused Path extractor panics.
                .route("/*path", any(proxy::proxy_handler))
                .layer(middleware::from_fn(auth_middleware))
                .layer(RequestBodyLimitLayer::new(cfg.max_body_kb * 1024))
                .with_state(state);

            let addr: SocketAddr = cfg.bind.parse()?;
            info!("🚀 SPeCK Bridge listening on http://{}", addr);
            info!("Backend: {}", cfg.backend_url);

            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }

        Commands::HashKey { key } => {
            let hash = hex::encode(sha2::Sha256::digest(key.as_bytes()));
            println!("{}", hash);
        }
    }

    Ok(())
}
EOF

# 10. Build
echo -e "${GREEN}▶ Building hardened release binary (may take 2–5 min first time)...${NC}"
cargo build --release --target aarch64-linux-android || {
    echo -e "${RED}→ Android-targeted build failed; retrying without explicit target...${NC}"
    cargo build --release
}

# Locate binary (host build first, then cross-compiled)
BINARY="$PROJECT/target/release/spck-llm-bridge"
if [ ! -f "$BINARY" ]; then
    BINARY="$PROJECT/target/aarch64-linux-android/release/spck-llm-bridge"
fi
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Binary not found after build — check cargo output above.${NC}"
    exit 1
fi
chmod +x "$BINARY"

# 11. Generate strong random key + config
echo -e "${YELLOW}→ Generating strong random auth key...${NC}"
RANDOM_KEY=$(openssl rand -hex 48)
HASH=$("$BINARY" hash-key "$RANDOM_KEY")

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

# 12. Start helper script
# FIX: Use --config flag (long arg) matching the #[arg(long)] Clap definition above.
cat > "$PROJECT/start-bridge.sh" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
cd "$PROJECT"
RUST_LOG=info exec "$BINARY" serve --config "$CONFIG_FILE"
EOF
chmod +x "$PROJECT/start-bridge.sh"

# 13. SPCK Plugin (hardened)
# FIX: reviewCode() called bare `generate(...)` which is out of scope inside the IIFE.
#      Must call `call('/api/generate', ...)` directly or use the returned object ref.
#      Restructured so all methods reference `call` via closure (already in scope).
PLUGIN_FILE="$PROJECT/spck-plugin.js"
cat > "$PLUGIN_FILE" <<EOF
// === SPeCK LLM Bridge Plugin (MAX OPSEC) ===
// Paste into SPCK JS console or save as a snippet.

window.SPeCKLLM = (() => {
    const BASE_URL = 'http://127.0.0.1:3030';
    let secretKey = null;

    const setKey = (k) => {
        if (!k || k.length < 20) throw new Error('Invalid key — must be 20+ chars');
        secretKey = k;
        console.log('✅ SPeCKLLM key set');
    };

    const call = async (endpoint, body, model = 'llama3.2') => {
        if (!secretKey) throw new Error('Call SPeCKLLM.setKey("your-key") first');
        const payload = { ...body, model };
        const res = await fetch(BASE_URL + endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Bridge-Key': secretKey,
            },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            const err = await res.text().catch(() => '(no body)');
            throw new Error(\`LLM bridge error (\${res.status}): \${err}\`);
        }
        return res.json();
    };

    // FIX: reviewCode previously called bare generate() which is not in scope inside an
    // IIFE returning an object literal. It now calls call() directly, which IS in scope.
    const reviewCode = async (model = 'llama3.2') => {
        const editor =
            window.monaco?.editor?.getModels()?.[0] ||
            document.querySelector('.monaco-editor')?.__monaco_editor;
        if (!editor) throw new Error('No Monaco editor found on page');
        const code = typeof editor.getValue === 'function'
            ? editor.getValue()
            : editor.getModel?.().getValue?.() ?? '';
        if (!code.trim()) throw new Error('Editor appears to be empty');
        const result = await call(
            '/api/generate',
            { prompt: \`Review this code for bugs, improvements, and best practices:\n\n\${code}\` },
            model,
        );
        return result.response ?? result;
    };

    return {
        setKey,
        chat:     (messages, model = 'llama3.2') =>
                      call('/v1/chat/completions', { messages }, model),
        complete: (prompt, model = 'llama3.2') =>
                      call('/v1/completions', { prompt }, model),
        generate: (prompt, model = 'llama3.2') =>
                      call('/api/generate', { prompt }, model).then(r => r.response ?? r),
        reviewCode,
    };
})();

// Auto-inject the key generated during install:
SPeCKLLM.setKey("$RANDOM_KEY");
console.log('🚀 SPeCKLLM ready! Try: SPeCKLLM.chat([{role:"user",content:"Hello"}])');
console.log('                   Or:   SPeCKLLM.reviewCode()');
EOF

echo -e "${GREEN}✅ Installation complete!${NC}"
echo "────────────────────────────────────────────────────────────"
echo -e "${GREEN}🔑 YOUR SECRET KEY (store securely, never share):${NC}"
echo -e "${YELLOW}$RANDOM_KEY${NC}"
echo ""
echo -e "${GREEN}📁 Config:${NC}      $CONFIG_FILE"
echo -e "${GREEN}📜 Plugin:${NC}      $PLUGIN_FILE"
echo -e "${GREEN}▶  Start:${NC}       $PROJECT/start-bridge.sh"
echo ""
echo "Steps to use:"
echo "  1. ollama serve &"
echo "  2. ollama pull llama3.2   (or: tinyllama for speed)"
echo "  3. $PROJECT/start-bridge.sh"
echo "  4. In SPCK console: paste contents of $PLUGIN_FILE"
echo "     Then: SPeCKLLM.chat([{role:'user', content:'Hello'}])"
echo ""
echo -e "${YELLOW}Tip:${NC} Keep everything on 127.0.0.1. Never expose port 3030 externally."
echo "────────────────────────────────────────────────────────────"
