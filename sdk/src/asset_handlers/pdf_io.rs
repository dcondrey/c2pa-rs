// Copyright 2023 Adobe. All rights reserved.
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

use std::{fs::File, path::Path};

use crate::{
    asset_handlers::pdf::{C2paPdf, Pdf},
    asset_io::{
        rename_or_move, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, ComposedManifestRef,
        HashBlockObjectType, HashObjectPositions,
    },
    utils::io_utils::tempfile_builder,
    Error::{self, JumbfNotFound, NotImplemented, PdfReadError},
};

static SUPPORTED_TYPES: [&str; 2] = ["pdf", "application/pdf"];
// Fixed-size placeholder used to materialize the manifest stream location during
// the reserve pass, before the real manifest bytes are known. The content length
// does not affect the resolved offset, which is determined by the objects written
// before the manifest stream.
static PLACEHOLDER_MANIFEST: &[u8] = &[0u8; 64];

pub struct PdfIO {}

impl CAIReader for PdfIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> crate::Result<Vec<u8>> {
        asset_reader.rewind()?;

        let pdf = Pdf::from_reader(asset_reader).map_err(|e| Error::InvalidAsset(e.to_string()))?;
        self.read_manifest_bytes(pdf)
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        if asset_reader.rewind().is_err() {
            return None;
        }

        let Ok(pdf) = Pdf::from_reader(asset_reader) else {
            return None;
        };

        self.read_xmp_from_pdf(pdf)
    }
}

impl PdfIO {
    fn read_manifest_bytes(&self, pdf: impl C2paPdf) -> crate::Result<Vec<u8>> {
        let Ok(result) = pdf.read_manifest_bytes() else {
            return Err(PdfReadError);
        };

        let Some(bytes) = result else {
            return Err(JumbfNotFound);
        };

        match bytes.as_slice() {
            [bytes] => Ok(bytes.to_vec()),
            _ => Err(NotImplemented(
                "c2pa-rs only supports reading PDFs with one manifest".into(),
            )),
        }
    }

    fn read_xmp_from_pdf(&self, pdf: impl C2paPdf) -> Option<String> {
        pdf.read_xmp()
    }
}

impl CAIWriter for PdfIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> crate::Result<()> {
        input_stream.rewind()?;
        let mut raw = Vec::new();
        input_stream.read_to_end(&mut raw)?;

        let mut pdf = Pdf::from_bytes(&raw).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        // lopdf cannot faithfully round-trip an encrypted PDF, so signing one
        // would corrupt it. Reject rather than produce an invalid asset.
        if pdf.is_password_protected() {
            return Err(Error::InvalidAsset(
                "cannot embed a C2PA manifest into an encrypted PDF".to_string(),
            ));
        }

        // When the asset already contains a manifest of the same length, finalize
        // it by patching the bytes in place. lopdf's load/save round-trip is not
        // byte-stable, so re-serializing here would shift bytes outside the
        // manifest and invalidate the hash computed over the placeholder asset.
        // A direct splice preserves every other byte exactly.
        if let Some((offset, length)) = pdf.c2pa_manifest_content_range(&raw) {
            if length == store_bytes.len() {
                output_stream.write_all(&raw[..offset])?;
                output_stream.write_all(store_bytes)?;
                output_stream.write_all(&raw[offset + length..])?;
                output_stream.flush()?;
                return Ok(());
            }
            pdf.replace_manifest_bytes(store_bytes.to_vec())
                .map_err(|e| Error::InvalidAsset(e.to_string()))?;
        } else {
            pdf.write_manifest_as_embedded_file(store_bytes.to_vec())
                .map_err(|e| Error::InvalidAsset(e.to_string()))?;
        }

        let mut buf = Vec::new();
        pdf.save_to(&mut buf)
            .map_err(|e| Error::InvalidAsset(e.to_string()))?;
        output_stream.write_all(&buf)?;
        output_stream.flush()?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> crate::Result<Vec<HashObjectPositions>> {
        input_stream.rewind()?;
        let mut raw = Vec::new();
        input_stream.read_to_end(&mut raw)?;

        let pdf = Pdf::from_bytes(&raw).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        // When a manifest is already embedded (the final hashing pass), its byte
        // range within `raw` is authoritative: this is exactly the region the
        // data hash must exclude.
        if let Some((offset, length)) = pdf.c2pa_manifest_content_range(&raw) {
            return Ok(vec![HashObjectPositions {
                offset,
                length,
                htype: HashBlockObjectType::Cai,
            }]);
        }

        // No manifest yet (the reserve pass): embed a placeholder, serialize, and
        // resolve the location it occupies. lopdf serialization is deterministic
        // and the manifest stream is written before the trailing objects, so this
        // offset matches the final signed asset.
        let mut pdf = pdf;
        pdf.write_manifest_as_embedded_file(PLACEHOLDER_MANIFEST.to_vec())
            .map_err(|e| Error::InvalidAsset(e.to_string()))?;

        let mut buf = Vec::new();
        pdf.save_to(&mut buf)
            .map_err(|e| Error::InvalidAsset(e.to_string()))?;

        let reloaded = Pdf::from_bytes(&buf).map_err(|e| Error::InvalidAsset(e.to_string()))?;
        let (offset, length) = reloaded
            .c2pa_manifest_content_range(&buf)
            .ok_or(Error::EmbeddingError)?;

        Ok(vec![HashObjectPositions {
            offset,
            length,
            htype: HashBlockObjectType::Cai,
        }])
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> crate::Result<()> {
        input_stream.rewind()?;
        let mut raw = Vec::new();
        input_stream.read_to_end(&mut raw)?;

        let mut pdf = Pdf::from_bytes(&raw).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        if pdf.has_c2pa_manifest() {
            pdf.remove_manifest_bytes()
                .map_err(|e| Error::InvalidAsset(e.to_string()))?;
            let mut buf = Vec::new();
            pdf.save_to(&mut buf)
                .map_err(|e| Error::InvalidAsset(e.to_string()))?;
            output_stream.write_all(&buf)?;
        } else {
            output_stream.write_all(&raw)?;
        }
        output_stream.flush()?;
        Ok(())
    }
}

impl AssetIO for PdfIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        Self {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(PdfIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(PdfIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> crate::Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> crate::Result<()> {
        let mut input = File::open(asset_path)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;
        self.write_cai(&mut input, &mut temp_file, store_bytes)?;
        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> crate::Result<Vec<HashObjectPositions>> {
        let mut file = File::open(asset_path)?;
        self.get_object_locations_from_stream(&mut file)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> crate::Result<()> {
        let mut input = File::open(asset_path)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;
        self.remove_cai_store_from_stream(&mut input, &mut temp_file)?;
        rename_or_move(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }
}

impl ComposedManifestRef for PdfIO {
    // Return entire CAI block as Vec<u8>
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>, Error> {
        Ok(manifest_data.to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("invalid file signature: {reason}")]
    InvalidFileSignature { reason: String },
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use crate::{
        asset_handlers,
        asset_handlers::{pdf::MockC2paPdf, pdf_io::PdfIO},
        asset_io::{AssetIO, CAIReader},
    };

    static MANIFEST_BYTES: &[u8; 2] = &[10u8, 20u8];

    #[test]
    fn test_error_reading_manifest_fails() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_manifest_bytes().returning(|| {
            Err(asset_handlers::pdf::Error::UnableToReadPdf(
                lopdf::Error::ReferenceLimit,
            ))
        });

        let pdf_io = PdfIO::new("pdf");
        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::PdfReadError)
        ))
    }

    #[test]
    fn test_no_manifest_found_returns_no_jumbf_error() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_manifest_bytes().returning(|| Ok(None));
        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_one_manifest_found_returns_bytes() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf
            .expect_read_manifest_bytes()
            .returning(|| Ok(Some(vec![MANIFEST_BYTES])));

        let pdf_io = PdfIO::new("pdf");
        assert_eq!(
            pdf_io.read_manifest_bytes(mock_pdf).unwrap(),
            MANIFEST_BYTES.to_vec()
        );
    }

    #[test]
    fn test_multiple_manifest_fail_with_not_implemented_error() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf
            .expect_read_manifest_bytes()
            .returning(|| Ok(Some(vec![MANIFEST_BYTES, MANIFEST_BYTES, MANIFEST_BYTES])));

        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::NotImplemented(_))
        ));
    }

    #[test]
    fn test_returns_none_when_no_xmp() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_xmp().returning(|| None);

        let pdf_io = PdfIO::new("pdf");
        assert_eq!(pdf_io.read_xmp_from_pdf(mock_pdf), None);
    }

    #[test]
    fn test_returns_some_when_some_xmp() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_xmp().returning(|| Some("xmp".into()));

        let pdf_io = PdfIO::new("pdf");
        assert!(pdf_io.read_xmp_from_pdf(mock_pdf).is_some());
    }

    #[test]
    fn test_cai_read_finds_no_manifest() {
        let source = crate::utils::test::fixture_path("basic.pdf");
        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_cai_store(&source),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_cai_read_xmp_finds_xmp_data() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut stream = Cursor::new(source.to_vec());

        let pdf_io = PdfIO::new("pdf");
        assert!(pdf_io.read_xmp(&mut stream).is_some());
    }

    #[test]
    fn test_read_cai_express_pdf_finds_single_manifest_store() {
        let source = include_bytes!("../../tests/fixtures/express-signed.pdf");
        let pdf_io = PdfIO::new("pdf");
        let mut pdf_stream = Cursor::new(source.to_vec());
        assert!(pdf_io.read_cai(&mut pdf_stream).is_ok());
    }

    // Embeds `store_bytes` into `basic.pdf` and returns the serialized PDF.
    fn embed(store_bytes: &[u8]) -> Vec<u8> {
        use crate::asset_io::CAIWriter;

        let source = include_bytes!("../../tests/fixtures/basic.pdf").to_vec();
        let pdf_io = PdfIO::new("pdf");
        let mut input = Cursor::new(source);
        let mut output = Cursor::new(Vec::new());
        pdf_io
            .write_cai(&mut input, &mut output, store_bytes)
            .unwrap();
        output.into_inner()
    }

    // The embedded manifest store must be recoverable after serialization, and the
    // resolved object location must exactly cover the manifest bytes — this range
    // is what the C2PA data hash excludes.
    #[test]
    fn test_object_location_exactly_covers_manifest() {
        use crate::asset_io::{CAIWriter, HashBlockObjectType};

        let store = vec![0xABu8; 4096];
        let pdf = embed(&store);

        let pdf_io = PdfIO::new("pdf");
        let mut stream = Cursor::new(pdf.clone());
        let locations = pdf_io
            .get_object_locations_from_stream(&mut stream)
            .unwrap();

        let cai = locations
            .iter()
            .find(|o| o.htype == HashBlockObjectType::Cai)
            .unwrap();

        assert_eq!(cai.length, store.len());
        assert!(cai.offset + cai.length <= pdf.len());
        assert_eq!(&pdf[cai.offset..cai.offset + cai.length], store.as_slice());

        // The recovered manifest must round-trip through the reader.
        let mut read_stream = Cursor::new(pdf);
        assert_eq!(pdf_io.read_cai(&mut read_stream).unwrap(), store);
    }

    // lopdf serialization must be deterministic so the placeholder-and-final two-pass
    // signing flow produces a stable hash: identical input yields identical bytes, and
    // repeated location queries yield identical ranges.
    #[test]
    fn test_serialization_and_locations_are_deterministic() {
        use crate::asset_io::CAIWriter;

        let store = vec![0x5Au8; 2048];
        let first = embed(&store);
        let second = embed(&store);
        assert_eq!(first, second, "lopdf serialization must be deterministic");

        let pdf_io = PdfIO::new("pdf");
        let mut s1 = Cursor::new(first.clone());
        let mut s2 = Cursor::new(first);
        assert_eq!(
            pdf_io.get_object_locations_from_stream(&mut s1).unwrap(),
            pdf_io.get_object_locations_from_stream(&mut s2).unwrap()
        );
    }

    // The binding invariant for the two-pass reserve/finalize flow: replacing an
    // embedded manifest with one of the same length (the placeholder -> signed
    // transition) must leave every byte outside the manifest content unchanged,
    // so the hash computed over the placeholder asset remains valid for the final
    // asset.
    #[test]
    fn test_same_size_replacement_is_byte_stable_outside_content() {
        use crate::asset_io::{CAIWriter, HashBlockObjectType};

        let placeholder = vec![0u8; 4096];
        let with_placeholder = embed(&placeholder);

        let pdf_io = PdfIO::new("pdf");
        let mut loc_stream = Cursor::new(with_placeholder.clone());
        let locations = pdf_io
            .get_object_locations_from_stream(&mut loc_stream)
            .unwrap();
        let cai = locations
            .iter()
            .find(|o| o.htype == HashBlockObjectType::Cai)
            .unwrap();

        // Finalize: write a different manifest of the same length over the asset
        // that already contains the placeholder (this is what `finish_save_stream`
        // does during signing).
        let finalized_manifest = vec![0xFFu8; placeholder.len()];
        let mut out = Cursor::new(Vec::new());
        pdf_io
            .write_cai(
                &mut Cursor::new(with_placeholder.clone()),
                &mut out,
                &finalized_manifest,
            )
            .unwrap();
        let finalized = out.into_inner();

        assert_eq!(with_placeholder.len(), finalized.len());
        assert_eq!(
            with_placeholder[..cai.offset],
            finalized[..cai.offset],
            "bytes before the manifest must be unchanged"
        );
        assert_eq!(
            with_placeholder[cai.offset + cai.length..],
            finalized[cai.offset + cai.length..],
            "bytes after the manifest must be unchanged"
        );
        assert_eq!(
            &finalized[cai.offset..cai.offset + cai.length],
            finalized_manifest.as_slice()
        );
    }

    // End-to-end: signing a PDF and reading it back must produce a valid hard binding.
    #[test]
    #[cfg(feature = "file_io")]
    fn test_sign_and_read_pdf_roundtrip() {
        use crate::{
            crypto::raw_signature::SigningAlg, utils::test_signer::test_signer, Builder, Reader,
        };

        let mut source = Cursor::new(include_bytes!("../../tests/fixtures/basic.pdf").to_vec());
        let mut dest = Cursor::new(Vec::new());

        let manifest = r#"{
            "title": "PDF Test",
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
                            }
                        ]
                    }
                }
            ]
        }"#;
        let mut builder = Builder::default().with_definition(manifest).unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        builder
            .sign(signer.as_ref(), "application/pdf", &mut source, &mut dest)
            .unwrap();

        dest.set_position(0);
        let reader = Reader::default()
            .with_stream("application/pdf", &mut dest)
            .unwrap();
        assert_eq!(reader.validation_status(), None);
    }
}
