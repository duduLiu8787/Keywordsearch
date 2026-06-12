use super::{DetectionReport, MatchRecord};
use anyhow::Result;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Serialize)]
#[serde(tag = "type")]
enum Envelope<'a> {
    #[serde(rename = "match")]
    Match(&'a MatchRecord),
    #[serde(rename = "detection")]
    Detection(&'a DetectionReport),
}

pub fn write<P: AsRef<Path>>(
    path: P,
    records: &[MatchRecord],
    detection: &DetectionReport,
) -> Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    for r in records {
        let env = Envelope::Match(r);
        serde_json::to_writer(&mut w, &env)?;
        w.write_all(b"\n")?;
    }
    let env = Envelope::Detection(detection);
    serde_json::to_writer(&mut w, &env)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}
