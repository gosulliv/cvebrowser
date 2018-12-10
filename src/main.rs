extern crate hyper;
extern crate rusqlite;
extern crate tokio;

mod cve;

use cve::CVE;
use hyper::rt::Future;
use hyper::service::service_fn_ok;
use hyper::{Body, Response, Server};
use rusqlite::{Statement, NO_PARAMS};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use std::fmt::Write;

fn main() {
    let addr = "127.0.0.1:12345".parse().unwrap();

    let new_svc = || {
        service_fn_ok(|req| {
            let connection = rusqlite::Connection::open("cve/cves").unwrap();
            let body_pattern = req.uri().query().unwrap();
            Response::new(Body::from(query(&connection, &body_pattern)))
        })
    };

    let server = Server::bind(&addr)
        .serve(new_svc)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server);
}

fn query(connection: &rusqlite::Connection, body_pattern: &str) -> String {
    let mut stmt = connection
        .prepare("SELECT * FROM CVE WHERE description LIKE (?)")
        .unwrap();
    let param = format!("%{}%", body_pattern);
    let mut iter = stmt
        .query_map(&[param], |row| CVE {
            name: row.get(0),
            status: row.get(1),
            description: row.get(2),
            refs: row.get(3),
            phase: row.get(4),
            votes: row.get(5),
            comments: row.get(6),
        }).unwrap();

    let mut res: String = "<table><tr><th>Name</th><th>Status</th><th>Description</th><th>Refs</th><th>Phase</th><th>Votes</th><th>Comments</th></tr>".into();
    for val in iter {
        let val = val.unwrap();
        write!(res, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            val.name,
            val.status,
            val.description,
            val.refs,
            val.phase,
            val.votes,
            val.comments,
        );
    }
    write!(res, "</table>");

    res
}
