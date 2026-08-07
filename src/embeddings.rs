//! RAG / embedding search over `package_embedding`.
//!
//! pgvector has no SeaORM column type, so the `vector(2050)` column is written
//! and searched through raw SQL here. The pure helpers (padding, literal
//! formatting, validation) are unit-tested without a database; the async
//! functions run Postgres-only SQL (they use pgvector's `halfvec` cast for the
//! ANN index, which SQLite has no equivalent for).

use anyhow::{Result, bail};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, Statement, Value};
use uuid::Uuid;

/// Fixed embedding width. A 1536- or 836-dim model is zero-padded to this; see
/// the schema note on why cosine similarity is preserved within one model.
pub const VECTOR_DIM: usize = 2050;

/// Validate a native embedding and zero-pad it to [`VECTOR_DIM`].
pub fn pad_to_dim(embedding: &[f32]) -> Result<Vec<f32>> {
    if embedding.is_empty() {
        bail!("embedding must be non-empty");
    }
    if embedding.len() > VECTOR_DIM {
        bail!(
            "embedding has {} dims, which exceeds the {VECTOR_DIM}-dim column",
            embedding.len()
        );
    }
    if let Some(bad) = embedding.iter().find(|v| !v.is_finite()) {
        bail!("embedding contains a non-finite value ({bad})");
    }
    let mut padded = Vec::with_capacity(VECTOR_DIM);
    padded.extend_from_slice(embedding);
    padded.resize(VECTOR_DIM, 0.0);
    Ok(padded)
}

/// Format a vector as a pgvector text literal: `[0.1,0.2,...]`.
pub fn to_pgvector_literal(embedding: &[f32]) -> String {
    let mut out = String::with_capacity(embedding.len() * 8 + 2);
    out.push('[');
    for (i, value) in embedding.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Compact but exact enough for f32 round-trip.
        out.push_str(&format!("{value}"));
    }
    out.push(']');
    out
}

/// A validated model name (matches the schema CHECK).
pub fn valid_model(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 120
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

/// Upsert a package's embedding for one model (re-embedding replaces in place).
/// Postgres-only. `native_dim` is the pre-padding width, recorded for
/// validation; `content` is the text that was embedded.
pub async fn upsert<C: ConnectionTrait>(
    db: &C,
    package_id: Uuid,
    model: &str,
    embedding: &[f32],
    content: &str,
) -> Result<()> {
    if !valid_model(model) {
        bail!("invalid embedding model name `{model}`");
    }
    let native_dim = embedding.len() as i32;
    let padded = pad_to_dim(embedding)?;
    let literal = to_pgvector_literal(&padded);
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(content.as_bytes()));

    // `?` binds are rewritten to $1.. for Postgres by SeaORM. The vector is
    // bound as text and cast; pgvector parses the `[...]` literal.
    let sql = "insert into package_embedding \
         (id, package_id, embedding_model, native_dimensions, embedding, content, content_sha256, created_at) \
         values (gen_random_uuid(), $1, $2, $3, $4::vector(2050), $5, $6, now()) \
         on conflict (package_id, embedding_model) do update set \
           native_dimensions = excluded.native_dimensions, \
           embedding = excluded.embedding, \
           content = excluded.content, \
           content_sha256 = excluded.content_sha256, \
           created_at = now()";
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [
            package_id.into(),
            model.into(),
            native_dim.into(),
            literal.into(),
            content.into(),
            sha.into(),
        ],
    ))
    .await?;
    Ok(())
}

/// One nearest-neighbour hit: the package id and its cosine distance (0 = same
/// direction, 2 = opposite).
#[derive(Debug, FromQueryResult)]
pub struct Neighbor {
    pub package_id: Uuid,
    pub distance: f64,
}

/// Cosine nearest-neighbour search within one model's embedding space.
/// Postgres-only; uses the `halfvec` cast so the HNSW index is used.
pub async fn search<C: ConnectionTrait>(
    db: &C,
    model: &str,
    query: &[f32],
    limit: u64,
) -> Result<Vec<Neighbor>> {
    if !valid_model(model) {
        bail!("invalid embedding model name `{model}`");
    }
    let padded = pad_to_dim(query)?;
    let literal = to_pgvector_literal(&padded);
    let limit = limit.clamp(1, 100) as i64;

    let sql = "select package_id, \
           (embedding::halfvec(2050) <=> $1::halfvec(2050))::float8 as distance \
         from package_embedding \
         where embedding_model = $2 \
         order by embedding::halfvec(2050) <=> $1::halfvec(2050) \
         limit $3";
    let rows = Neighbor::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [Value::from(literal), model.into(), limit.into()],
    ))
    .all(db)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_smaller_dims_to_2050() {
        let v = vec![1.0f32, 2.0, 3.0];
        let padded = pad_to_dim(&v).unwrap();
        assert_eq!(padded.len(), VECTOR_DIM);
        assert_eq!(&padded[..3], &[1.0, 2.0, 3.0]);
        assert!(padded[3..].iter().all(|&x| x == 0.0));
    }

    #[test]
    fn accepts_1536_and_836_and_exact_2050() {
        assert_eq!(pad_to_dim(&vec![0.5; 1536]).unwrap().len(), 2050);
        assert_eq!(pad_to_dim(&vec![0.5; 836]).unwrap().len(), 2050);
        assert_eq!(pad_to_dim(&vec![0.5; 2050]).unwrap().len(), 2050);
    }

    #[test]
    fn rejects_oversized_empty_and_nonfinite() {
        assert!(pad_to_dim(&vec![0.1; 2051]).is_err());
        assert!(pad_to_dim(&[]).is_err());
        assert!(pad_to_dim(&[1.0, f32::NAN]).is_err());
        assert!(pad_to_dim(&[1.0, f32::INFINITY]).is_err());
    }

    #[test]
    fn pgvector_literal_format() {
        assert_eq!(to_pgvector_literal(&[1.0, 2.5, -3.0]), "[1,2.5,-3]");
        assert_eq!(to_pgvector_literal(&[]), "[]");
    }

    #[test]
    fn zero_padding_preserves_cosine_within_a_model() {
        // Cosine(a,b) must be identical before and after zero-padding: the
        // extra zeros add nothing to the dot product or either norm.
        let a = vec![0.3f32, 0.4, 0.5, 0.1];
        let b = vec![0.2f32, 0.9, 0.1, 0.4];
        let cos = |x: &[f32], y: &[f32]| {
            let dot: f32 = x.iter().zip(y).map(|(p, q)| p * q).sum();
            let nx: f32 = x.iter().map(|p| p * p).sum::<f32>().sqrt();
            let ny: f32 = y.iter().map(|q| q * q).sum::<f32>().sqrt();
            dot / (nx * ny)
        };
        let before = cos(&a, &b);
        let after = cos(&pad_to_dim(&a).unwrap(), &pad_to_dim(&b).unwrap());
        assert!(
            (before - after).abs() < 1e-6,
            "cosine changed: {before} vs {after}"
        );
    }

    #[test]
    fn model_name_validation() {
        assert!(valid_model("openai/text-embedding-3-small"));
        assert!(valid_model("bge-small-en-v1.5"));
        assert!(!valid_model(""));
        assert!(!valid_model("bad name with spaces"));
        assert!(!valid_model(&"x".repeat(121)));
    }
}
