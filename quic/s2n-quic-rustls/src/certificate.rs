// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use rustls::{pki_types, Error};

macro_rules! cert_type {
    ($name:ident, $trait:ident, $method:ident, $inner:ty) => {
        pub struct $name(pub(crate) $inner);

        pub trait $trait {
            fn $method(self) -> Result<$name, Error>;
        }

        impl $trait for $name {
            fn $method(self) -> Result<$name, Error> {
                Ok(self)
            }
        }

        impl $trait for String {
            fn $method(self) -> Result<$name, Error> {
                let cert = pem::$method(self.as_bytes())?;
                Ok($name(cert))
            }
        }

        impl $trait for &String {
            fn $method(self) -> Result<$name, Error> {
                let cert = pem::$method(self.as_bytes())?;
                Ok($name(cert))
            }
        }

        impl $trait for &str {
            fn $method(self) -> Result<$name, Error> {
                let cert = pem::$method(self.as_bytes())?;
                Ok($name(cert))
            }
        }

        impl $trait for Vec<u8> {
            fn $method(self) -> Result<$name, Error> {
                let cert = der::$method(self)?;
                Ok($name(cert))
            }
        }

        impl $trait for &[u8] {
            fn $method(self) -> Result<$name, Error> {
                self.to_vec().$method()
            }
        }

        impl $trait for &std::path::Path {
            fn $method(self) -> Result<$name, Error> {
                match self.extension() {
                    Some(ext) if ext == "der" => {
                        let pem =
                            std::fs::read(self).map_err(|err| Error::General(err.to_string()))?;
                        pem.$method()
                    }
                    _ => {
                        let pem = std::fs::read_to_string(self)
                            .map_err(|err| Error::General(err.to_string()))?;
                        pem.$method()
                    }
                }
            }
        }
    };
}

cert_type!(
    PrivateKey,
    IntoPrivateKey,
    into_private_key,
    pki_types::PrivateKeyDer<'static>
);
cert_type!(
    Certificate,
    IntoCertificate,
    into_certificate,
    Vec<pki_types::CertificateDer<'static>>
);

mod pem {
    use super::*;

    pub fn into_certificate(
        contents: &[u8],
    ) -> Result<Vec<pki_types::CertificateDer<'static>>, Error> {
        let mut cursor = std::io::Cursor::new(contents);
        let certs = rustls_pemfile::certs(&mut cursor)
            .map(|certs| certs.into_iter().map(pki_types::CertificateDer::from))
            .flatten()
            .collect();
        // .map_err(|_| Error::General("Could not read certificate".to_string()))?;
        Ok(certs)
    }

    pub fn into_private_key(contents: &[u8]) -> Result<pki_types::PrivateKeyDer<'static>, Error> {
        let mut cursor = std::io::Cursor::new(contents);

        let mut private_keys = rustls_pemfile::read_all(&mut cursor)
            .filter(|v| v.is_ok())
            .collect::<Vec<_>>();

        if private_keys.len() > 1 {
            return Err(Error::General(format!(
                "Unexpected number of keys: {} (only 1 supported)",
                private_keys.len()
            )));
        }
        if private_keys.is_empty() {
            return Err(Error::General(
                "could not load any valid private keys".to_string(),
            ));
        }

        let key = match private_keys.pop().unwrap().unwrap() {
            rustls_pemfile::Item::Pkcs1Key(key) => pki_types::PrivateKeyDer::from(key),
            rustls_pemfile::Item::Pkcs8Key(key) => pki_types::PrivateKeyDer::from(key),
            _ => return Err(Error::General("unhandled item".to_string())),
        };

        Ok(key)
    }
}

mod der {
    use super::*;
    use pkcs8::der::Decode;

    pub fn into_certificate(
        contents: Vec<u8>,
    ) -> Result<Vec<pki_types::CertificateDer<'static>>, Error> {
        // der files only have a single cert
        Ok(vec![pki_types::CertificateDer::from(contents)])
    }

    pub fn into_private_key(contents: Vec<u8>) -> Result<pki_types::PrivateKeyDer<'static>, Error> {
        if let Ok(_) = pkcs8::PrivateKeyInfo::from_der(&contents) {
            return Ok(pki_types::PrivateKeyDer::from(
                pki_types::PrivatePkcs8KeyDer::from(contents),
            ));
        };

        if let Ok(_) = pkcs1::RsaPrivateKey::from_der(&contents) {
            return Ok(pki_types::PrivateKeyDer::from(
                pki_types::PrivatePkcs1KeyDer::from(contents),
            ));
        };

        Err(Error::General("Could not read private key".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_quic_core::crypto::tls::testing::certificates::*;

    #[test]
    fn load() {
        let _ = CERT_PEM.into_certificate().unwrap();
        let _ = CERT_DER.into_certificate().unwrap();

        let _ = KEY_PEM.into_private_key().unwrap();
        let _ = KEY_DER.into_private_key().unwrap();
    }
}
