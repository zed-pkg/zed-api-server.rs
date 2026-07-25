//! unpkg-style edge serving of package contents: extract one file from a
//! stored artifact so the web can consume packages without installing them.

use std::io::{Cursor, Read};

use axum::http::header::{self, HeaderName, HeaderValue};
use flate2::read::GzDecoder;
use zed_interfaces::artifact::ArtifactFormat;

/// Cache policy for served package files: content is sha-addressed and
/// immutable, so it can be cached indefinitely.
const IMMUTABLE_CACHE: &str = "public, max-age=31536000, immutable";

/// Largest single file served out of an artifact. Also the allocation cap:
/// archive headers declare sizes and are attacker-controlled, so they are
/// never trusted for buffer sizing.
pub const MAX_SERVED_FILE_BYTES: u64 = 25 * 1024 * 1024;

/// Aggregate cap on bytes inflated out of one artifact while locating a single
/// entry.
///
/// [`MAX_SERVED_FILE_BYTES`] only bounds the *matched* entry, which is not
/// enough for tar.gz: `GzDecoder` is not `Seek`, so `tar`'s skip path
/// read-and-discards, meaning every non-matching entry is fully decompressed on
/// the way past. Without an aggregate budget, a highly compressible artifact
/// (gzip tops out near 1030:1) turns one unauthenticated request for a
/// nonexistent path into hundreds of gigabytes of inflation.
///
/// The budget has to exceed the largest legitimate *uncompressed* package,
/// since finding a file may require scanning the whole archive — hence a cap
/// far above `MAX_ARTIFACT_BYTES` rather than a tight one.
/// Override with `ZED_MAX_INFLATED_BYTES`.
const DEFAULT_MAX_INFLATED_BYTES: u64 = 512 * 1024 * 1024;

pub fn max_inflated_bytes() -> u64 {
    std::env::var("ZED_MAX_INFLATED_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_INFLATED_BYTES)
}

#[derive(Debug)]
pub enum ExtractError {
    /// The entry is larger than [`MAX_SERVED_FILE_BYTES`] (declared or actual).
    TooLarge,
    /// The archive inflates past [`max_inflated_bytes`] — a decompression bomb,
    /// or simply a package too large to serve single files out of.
    InflationBudgetExceeded,
    /// The archive could not be read.
    Archive(anyhow::Error),
}

/// Reader that enforces a total-bytes budget across the whole archive scan.
struct BudgetReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                INFLATION_BUDGET_MSG,
            ));
        }
        let want = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..want])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Sentinel carried on the io::Error so the budget stop can be told apart from
/// a genuinely corrupt archive after `tar` has wrapped it.
const INFLATION_BUDGET_MSG: &str = "zed: archive exceeded the decompression budget";

fn is_budget_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.to_string().contains(INFLATION_BUDGET_MSG))
    }) || err.to_string().contains(INFLATION_BUDGET_MSG)
}

impl From<std::io::Error> for ExtractError {
    fn from(err: std::io::Error) -> Self {
        Self::Archive(err.into())
    }
}

impl From<zip::result::ZipError> for ExtractError {
    fn from(err: zip::result::ZipError) -> Self {
        Self::Archive(err.into())
    }
}

/// Find `pkg/<rel_path>` inside a stored artifact of the given format.
pub fn extract_file(
    archive: &[u8],
    format: ArtifactFormat,
    rel_path: &str,
) -> Result<Option<Vec<u8>>, ExtractError> {
    let want = format!("{}/{rel_path}", zed_interfaces::paths::ARCHIVE_ROOT);
    match format {
        ArtifactFormat::TarGz => {
            // Budget the *inflated* stream, not the compressed input: skipping
            // past unmatched entries decompresses them in full (see
            // [`max_inflated_bytes`]).
            let budgeted = BudgetReader {
                inner: GzDecoder::new(archive),
                // +1 so an archive of exactly the budget still scans cleanly.
                remaining: max_inflated_bytes().saturating_add(1),
            };
            let mut tar = tar::Archive::new(budgeted);
            let entries = tar.entries().map_err(map_tar_err)?;
            for entry in entries {
                let entry = entry.map_err(map_tar_err)?;
                if entry.path().map_err(map_tar_err)?.to_string_lossy() == want {
                    if entry.size() > MAX_SERVED_FILE_BYTES {
                        return Err(ExtractError::TooLarge);
                    }
                    return Ok(Some(read_capped(entry)?));
                }
            }
            Ok(None)
        }
        ArtifactFormat::Zip => {
            let mut zip = zip::ZipArchive::new(Cursor::new(archive))?;
            let entry = match zip.by_name(&want) {
                Ok(entry) => entry,
                Err(zip::result::ZipError::FileNotFound) => return Ok(None),
                Err(err) => return Err(err.into()),
            };
            if entry.size() > MAX_SERVED_FILE_BYTES {
                return Err(ExtractError::TooLarge);
            }
            Ok(Some(read_capped(entry)?))
        }
    }
}

/// Translate a tar error, preserving the budget stop as its own variant rather
/// than letting it collapse into a generic (500-mapped) archive error.
fn map_tar_err(err: std::io::Error) -> ExtractError {
    if err.to_string().contains(INFLATION_BUDGET_MSG) {
        return ExtractError::InflationBudgetExceeded;
    }
    let wrapped: anyhow::Error = err.into();
    if is_budget_error(&wrapped) {
        return ExtractError::InflationBudgetExceeded;
    }
    ExtractError::Archive(wrapped)
}

/// Read a whole entry without trusting its declared size: never allocate up
/// front, stop at the cap + 1, and reject if the actual bytes exceed the cap.
fn read_capped<R: Read>(reader: R) -> Result<Vec<u8>, ExtractError> {
    let mut buf = Vec::new();
    std::io::copy(&mut reader.take(MAX_SERVED_FILE_BYTES + 1), &mut buf).map_err(map_tar_err)?;
    if buf.len() as u64 > MAX_SERVED_FILE_BYTES {
        return Err(ExtractError::TooLarge);
    }
    Ok(buf)
}

/// Best-effort content-type guess from a file extension. This is the *raw*
/// guess; user-published files are served through [`served_mime`], which
/// neutralizes active-content types before they reach a browser.
pub fn mime_for(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or_default() {
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "html" | "htm" => "text/html; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "wasm" => "application/wasm",
        "toml" => "application/toml",
        "md" | "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Content types a browser executes in the page's origin. Package contents are
/// author-controlled, so serving any of these as-is from the trusted registry
/// origin is a stored-XSS vector (H2).
fn is_active_content(mime: &str) -> bool {
    let base = mime.split(';').next().unwrap_or(mime).trim();
    matches!(
        base,
        "text/html" | "image/svg+xml" | "application/xhtml+xml"
    ) || base.contains("javascript")
}

/// The content-type a single package file is *served* with. HTML/SVG/XHTML/JS
/// are downgraded to `text/plain` so author-published markup or scripts cannot
/// execute from the registry origin (H2); everything else keeps its guess.
pub fn served_mime(path: &str) -> &'static str {
    let guessed = mime_for(path);
    if is_active_content(guessed) {
        "text/plain; charset=utf-8"
    } else {
        guessed
    }
}

/// Response headers for every `/v1/files` (unpkg-style) response. Beyond the
/// neutralized content-type, user content is served `inline` under a `sandbox`
/// CSP so it is inert as active content even if a browser guesses otherwise
/// (H2). `X-Content-Type-Options: nosniff` is applied globally by the router.
pub fn served_file_headers(path: &str) -> [(HeaderName, HeaderValue); 4] {
    [
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static(served_mime(path)),
        ),
        (
            header::CACHE_CONTROL,
            HeaderValue::from_static(IMMUTABLE_CACHE),
        ),
        (
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        ),
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("sandbox"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn tiny_archive() -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let data = b"body { color: orange }";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "pkg/dist/style.css", data.as_slice())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn tiny_zip() -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "pkg/dist/style.css",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(b"body { color: orange }").unwrap();
        writer.finish().unwrap().into_inner()
    }

    /// A tar.gz whose only entry declares `declared` bytes but carries none:
    /// the size cap must trip on the header alone, before any allocation.
    fn lying_archive(declared: u64) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut header = tar::Header::new_gnu();
        header.set_path("pkg/huge.bin").unwrap();
        header.set_size(declared);
        header.set_mode(0o644);
        header.set_cksum();
        encoder.write_all(header.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extracts_by_relative_path() {
        let archive = tiny_archive();
        let found = extract_file(&archive, ArtifactFormat::TarGz, "dist/style.css").unwrap();
        assert_eq!(found.unwrap(), b"body { color: orange }");
        assert!(
            extract_file(&archive, ArtifactFormat::TarGz, "missing.css")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn zip_extracts_by_relative_path() {
        let archive = tiny_zip();
        let found = extract_file(&archive, ArtifactFormat::Zip, "dist/style.css").unwrap();
        assert_eq!(found.unwrap(), b"body { color: orange }");
        assert!(
            extract_file(&archive, ArtifactFormat::Zip, "missing.css")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_oversized_declared_entry() {
        let archive = lying_archive(MAX_SERVED_FILE_BYTES + 1);
        let err = extract_file(&archive, ArtifactFormat::TarGz, "huge.bin").unwrap_err();
        assert!(matches!(err, ExtractError::TooLarge));
    }

    /// A tar.gz of `entries` highly-compressible entries of `each` bytes, none
    /// of which is the file we ask for — so the scan must skip past all of them.
    fn compressible_archive(entries: usize, each: usize) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let zeros = vec![0u8; each];
        for i in 0..entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("pkg/filler-{i}.bin")).unwrap();
            header.set_size(each as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &zeros[..]).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// Skipping past unmatched tar entries fully inflates them (GzDecoder is
    /// not Seek), so without an aggregate budget one unauthenticated request
    /// for a path that isn't in the archive inflates the entire bomb.
    #[test]
    fn aggregate_inflation_budget_stops_a_gzip_bomb() {
        // 64 MiB inflated, ~64 KiB on the wire.
        let archive = compressible_archive(64, 1024 * 1024);
        assert!(
            archive.len() < 1024 * 1024,
            "bomb should be tiny compressed, got {} bytes",
            archive.len()
        );

        // Budget below the inflated size => the scan is cut off rather than
        // inflating everything looking for a name that isn't there.
        temp_env_var("ZED_MAX_INFLATED_BYTES", "8388608", || {
            let err = extract_file(&archive, ArtifactFormat::TarGz, "not-here.bin").unwrap_err();
            assert!(
                matches!(err, ExtractError::InflationBudgetExceeded),
                "expected budget stop, got {err:?}"
            );
        });

        // Budget above it => an honest (if large) archive still scans cleanly
        // and reports a genuine miss.
        temp_env_var("ZED_MAX_INFLATED_BYTES", "134217728", || {
            let found = extract_file(&archive, ArtifactFormat::TarGz, "not-here.bin").unwrap();
            assert!(found.is_none());
        });
    }

    /// The budget must not break ordinary lookups.
    #[test]
    fn budget_does_not_affect_normal_extraction() {
        let archive = tiny_archive();
        let found = extract_file(&archive, ArtifactFormat::TarGz, "dist/style.css").unwrap();
        assert_eq!(found.unwrap(), b"body { color: orange }");
    }

    /// Env mutation is process-global; keep it scoped and serialized so these
    /// tests can't leak into the rest of the suite.
    fn temp_env_var(key: &str, value: &str, f: impl FnOnce()) {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        f();
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn mime_guessing() {
        assert_eq!(mime_for("dist/style.css"), "text/css; charset=utf-8");
        assert_eq!(mime_for("mod.wasm"), "application/wasm");
        assert_eq!(mime_for("weird.bin"), "application/octet-stream");
    }

    #[test]
    fn active_content_is_neutralized_to_text_plain() {
        // Author-controlled markup/scripts must never be served as active
        // content from the registry origin (H2).
        for path in ["index.html", "page.htm", "app.js", "m.mjs", "icon.svg"] {
            assert_eq!(
                served_mime(path),
                "text/plain; charset=utf-8",
                "{path} should be neutralized"
            );
        }
        // Inert types keep their guessed content-type.
        assert_eq!(served_mime("style.css"), "text/css; charset=utf-8");
        assert_eq!(served_mime("logo.png"), "image/png");
        assert_eq!(served_mime("mod.wasm"), "application/wasm");
    }

    #[test]
    fn html_and_svg_are_served_sandboxed_as_text_plain() {
        for path in ["index.html", "icon.svg"] {
            let headers = served_file_headers(path);
            let get = |name: &HeaderName| {
                headers
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, v)| v.clone())
                    .unwrap()
            };
            assert_eq!(get(&header::CONTENT_TYPE), "text/plain; charset=utf-8");
            assert_eq!(get(&header::CONTENT_SECURITY_POLICY), "sandbox");
            assert_eq!(get(&header::CONTENT_DISPOSITION), "inline");
        }
    }
}
