// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

/// Converts a file extension to a MIME type
pub fn extension_to_mime(extension: &str) -> Option<&'static str> {
    Some(match extension.to_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "psd" => "image/vnd.adobe.photoshop",
        "tiff" | "tif" => "image/tiff",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "dng" => "image/x-adobe-dng",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "mp2" | "mpa" | "mpe" | "mpeg" | "mpg" | "mpv2" => "video/mpeg",
        "mp4" => "video/mp4",
        "avi" => "video/avi",
        "avif" => "image/avif",
        "mov" | "qt" => "video/quicktime",
        "m4a" => "audio/mp4",
        "mid" | "rmi" => "audio/mid",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "aif" | "aifc" | "aiff" => "audio/aiff",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "ai" => "application/postscript",
        "arw" => "image/x-sony-arw",
        "nef" => "image/x-nikon-nef",
        "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => "application/c2pa",
        _ => return None,
    })
}

/// Convert a format to a MIME type
/// formats can be passed in as extensions, e.g. "jpg" or "jpeg"
/// or as MIME types, e.g. "image/jpeg"
pub fn format_to_mime(format: &str) -> String {
    match extension_to_mime(format) {
        Some(mime) => mime,
        None => format,
    }
    .to_string()
}

/// Converts a format to a file extension
#[cfg(feature = "file_io")]
pub fn format_to_extension(format: &str) -> Option<&'static str> {
    Some(match format.to_lowercase().as_str() {
        "jpg" | "jpeg" | "image/jpeg" => "jpg",
        "png" | "image/png" => "png",
        "gif" | "image/gif" => "gif",
        "psd" | "image/vnd.adobe.photoshop" => "psd",
        "tiff" | "tif" | "image/tiff" => "tiff",
        "svg" | "image/svg+xml" => "svg",
        "ico" | "image/x-icon" => "ico",
        "bmp" | "image/bmp" => "bmp",
        "webp" | "image/webp" => "webp",
        "dng" | "image/dng" => "dng",
        "heic" | "image/heic" => "heic",
        "heif" | "image/heif" => "heif",
        "mp2" | "mpa" | "mpe" | "mpeg" | "mpg" | "mpv2" | "video/mpeg" => "mp2",
        "mp4" | "video/mp4" => "mp4",
        "avif" | "image/avif" => "avif",
        "avi" | "video/avi" => "avi",
        "mov" | "qt" | "video/quicktime" => "mov",
        "m4a" | "audio/mp4" => "m4a",
        "mid" | "rmi" | "audio/mid" => "mid",
        "mp3" | "audio/mpeg" => "mp3",
        "wav" | "audio/wav" | "audio/wave" | "audio.vnd.wave" => "wav",
        "aif" | "aifc" | "aiff" | "audio/aiff" => "aif",
        "ogg" | "audio/ogg" => "ogg",
        "pdf" | "application/pdf" => "pdf",
        "ai" | "application/postscript" => "ai",
        "arw" | "image/x-sony-arw" => "arw",
        "nef" | "image/x-nikon-nef" => "nef",
        "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => "c2pa",
        _ => return None,
    })
}

/// Return a MIME type given a file path.
///
/// This function will use the file extension to determine the MIME type.
/// If the extension is not recognized, it will attempt to detect the format from the file content.
pub fn format_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    let path = path.as_ref();
    path.extension()
        .and_then(|ext| extension_to_mime(ext.to_string_lossy().to_lowercase().as_ref()))
        .map(|m| m.to_owned())
        .or_else(|| {
            // try to detect from content
            #[cfg(feature = "file_io")]
            {
                use std::io::Read;
                std::fs::File::open(path).ok().and_then(|mut file| {
                    let mut buffer = [0u8; 512];
                    let n = file.read(&mut buffer).ok()?;
                    get_mime_from_bytes(&buffer[..n]).map(|m| m.to_string())
                })
            }
            #[cfg(not(feature = "file_io"))]
            None
        })
}

/// Returns a MIME type given a stream of bytes.
#[allow(dead_code)]
pub fn get_mime_from_bytes(data: &[u8]) -> Option<&'static str> {
    if data.len() < 2 {
        return None;
    }

    // JPEG: FF D8 FF
    if data.len() >= 3 && data.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.starts_with(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some("image/png");
    }

    // GIF: GIF87a or GIF89a
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
    }

    // TIFF: II* (little endian) or MM* (big endian)
    if data.starts_with(&[0x49, 0x49, 0x2a, 0x00]) || data.starts_with(&[0x4d, 0x4d, 0x00, 0x2a]) {
        return Some("image/tiff");
    }

    // BMP: BM
    if data.starts_with(b"BM") {
        return Some("image/bmp");
    }

    // PDF: %PDF-
    if data.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }

    // RIFF formats (WEBP, WAV, AVI)
    if data.starts_with(b"RIFF") && data.len() >= 12 {
        let riff_type = &data[8..12];
        if riff_type == b"WEBP" {
            return Some("image/webp");
        }
        if riff_type == b"WAVE" {
            return Some("audio/wav");
        }
        if riff_type == b"AVI " {
            return Some("video/avi");
        }
    }

    // MP3 (ID3 tag)
    if data.starts_with(b"ID3") {
        return Some("audio/mpeg");
    }
    // MP3 sync frame (simplified)
    if data.len() >= 2 && data[0] == 0xff && (data[1] & 0xe0) == 0xe0 {
        return Some("audio/mpeg");
    }

    // BMFF (ISO Base Media File Format: mp4, mov, heic, avif, etc.)
    // Check for "ftyp" at offset 4
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        let brand = &data[8..12];
        return match brand {
            b"mp41" | b"mp42" | b"isom" | b"iso2" | b"iso3" | b"iso4" | b"iso5" | b"iso6" | b"avc1" | b"mp71" => {
                Some("video/mp4")
            }
            b"m4a " => Some("audio/mp4"),
            b"m4v " => Some("video/x-m4v"),
            b"heic" | b"heix" | b"mif1" | b"msf1" => Some("image/heic"),
            b"hevc" | b"hevx" => Some("image/heif"),
            b"avif" | b"avis" => Some("image/avif"),
            b"qt  " => Some("video/quicktime"),
            b"3gp1" | b"3gp2" | b"3gp3" | b"3gp4" | b"3gp5" | b"3gp6" | b"3gr6" | b"3gs6" | b"3ge6" => {
                Some("video/3gpp")
            }
            b"3g2a" | b"3g2b" | b"3g2c" => Some("video/3g2"),
            _ => None,
        };
    }

    // SVG
    // Check for "<svg" or "<?xml" followed by "<svg"
    let header_len = std::cmp::min(data.len(), 512);
    if let Ok(header) = std::str::from_utf8(&data[..header_len]) {
        let header = header.trim_start();
        if header.starts_with("<svg") || (header.starts_with("<?xml") && header.contains("<svg")) {
            return Some("image/svg+xml");
        }
    }

    // C2PA / JUMBF
    // JUMBF starts with a box size then 'jumb'
    if data.len() >= 8 && &data[4..8] == b"jumb" {
        return Some("application/c2pa");
    }

    None
}
