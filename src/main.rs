extern crate rusqlite;

use rusqlite::{Connection, NO_PARAMS};

#[derive(Debug)]
struct CVE {
    name: String,
    status: String,
    description: String,
    refs: String,
    phase: String,
    votes: String,
    comments: String,
}

fn main() {
    let conn = Connection::open("cve/cves").unwrap();

    let mut stmt = conn
        .prepare("SELECT * FROM CVE")
        .unwrap();

    let cve_iter = stmt
        .query_map(NO_PARAMS, |row| CVE {
            name: row.get( 0),
            status: row.get( 1),
            description: row.get( 2),
            refs: row.get( 3),
            phase: row.get( 4),
            votes: row.get( 5),
            comments: row.get( 6),
        }).unwrap();


    let mut counter = 0;

    for cve in cve_iter {
        //if counter > 100 { return; }
        match cve {
            Ok(x) => println!("Found cve #{} {:?}", counter, x),
            Err(x) => println!("CVE {} has issues, error {:?}", counter, x),
        }
        counter += 1;
    }
}
