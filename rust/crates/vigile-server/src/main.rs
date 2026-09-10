// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile server binary — serves the admin API and web portal.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8443);

    let state = match vigile_server::ServerState::lab() {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => {
            eprintln!("vigile-server: failed to initialize server state: {e}");
            std::process::exit(1);
        }
    };

    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap_or_else(|e| {
        eprintln!("vigile-server: cannot bind 127.0.0.1:{port}: {e}");
        std::process::exit(1);
    });

    println!(
        "vigile-server {} listening on http://127.0.0.1:{port}",
        env!("CARGO_PKG_VERSION")
    );
    println!("Web portal: http://127.0.0.1:{port}/");
    println!("Admin API:  http://127.0.0.1:{port}/admin/v1/status");
    println!();
    println!("Press Ctrl+C to stop.");

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let Ok(mut st) = state.lock() else { continue };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));

        match vigile_server::http::parse_request(&mut stream) {
            Ok(request) => {
                // Serve the web portal at the root path
                if request.method == "GET" && (request.path == "/" || request.path == "/index.html")
                {
                    serve_portal(&mut stream);
                } else {
                    let _ = vigile_server::routes::route(&mut stream, &request, &mut st, None);
                }
            }
            Err(e) => {
                let _ = vigile_server::http::error_response(&mut stream, &e);
            }
        }
    }
}

fn serve_portal(stream: &mut std::net::TcpStream) {
    let html = std::fs::read_to_string("web/index.html")
        .or_else(|_| std::fs::read_to_string("../web/index.html"))
        .or_else(|_| std::fs::read_to_string("/usr/share/vigile/web/index.html"))
        .unwrap_or_else(|_| {
            "<html><body><h1>Vigile</h1><p>Portal file not found.</p></body></html>".to_string()
        });
    let _ = vigile_server::http::write_response(
        stream,
        200,
        "OK",
        "text/html; charset=utf-8",
        html.as_bytes(),
    );
}
