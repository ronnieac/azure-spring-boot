/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.utils;

import static com.microsoft.azure.utils.FileLoader.getAllBytesFromFile;
import static com.microsoft.azure.utils.FileLoader.getInputStreamFromFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;

public interface CertificateLoader {

    static PrivateKey getPrivateKey(final String filename) {
        try {
            final byte[] encodedBytes = getAllBytesFromFile(filename);
            final String encodedKey = new String(encodedBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
            final byte[] decodedBytes = Base64.decodeBase64(encodedKey);
            final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedBytes);
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    static X509Certificate getPublicCertificate(final String filename) {
        try (InputStream inputStream = getInputStreamFromFile(filename)) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
