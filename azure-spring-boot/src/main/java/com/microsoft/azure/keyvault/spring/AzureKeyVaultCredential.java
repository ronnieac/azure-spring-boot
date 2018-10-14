/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.keyvault.spring;

import com.microsoft.aad.adal4j.AsymmetricKeyCredential;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;

import com.microsoft.azure.utils.CertificateLoader;
import com.microsoft.azure.utils.FileLoader;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.*;
import java.util.function.BiFunction;
import lombok.Builder;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;


public class AzureKeyVaultCredential extends KeyVaultCredentials {

    private final AzureKeyVaultCredentialProperties properties;

    public AzureKeyVaultCredential(AzureKeyVaultCredentialProperties properties) {
        this.properties = properties;
    }

    @Override
    public String doAuthenticate(String authorization, String resource, String scope) {
        AuthenticationContext context = null;
        AuthenticationResult result = null;
        String token = "";
        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        try {
            context = new AuthenticationContext(authorization, false, executorService);
            final AuthenticationType authenticationType = AuthenticationType
                .getFromProperties(properties);
            final Future<AuthenticationResult> future = authenticationType
                .acquireToken(properties, context, resource);
            result = future.get(properties.getTimeoutInSeconds(), TimeUnit.SECONDS);
            token = result.getAccessToken();
        } catch (MalformedURLException | TimeoutException | InterruptedException | ExecutionException ex) {
            throw new IllegalStateException("Failed to do authentication.", ex);
        } finally {
            executorService.shutdown();
        }
        return token;
    }


    @Data
    @Builder
    public static class AzureKeyVaultCredentialProperties {

        private static final long DEFAULT_TOKEN_ACQUIRE_TIMEOUT_IN_SECONDS = 60L;

        private String clientId;
        private String clientKey;
        private String clientPfxFile;
        private String clientPfxPassword;
        private String clientPublicCertificate;
        private String clientPrivateKey;
        private long timeoutInSeconds = DEFAULT_TOKEN_ACQUIRE_TIMEOUT_IN_SECONDS;
    }

    private enum AuthenticationType {

        CLIENT_KEY {
            @Override
            Future<AuthenticationResult> acquireToken(AzureKeyVaultCredentialProperties properties,
                AuthenticationContext context, String resource) {
                final ClientCredential credential = new ClientCredential(
                    properties.getClientId(), properties.getClientKey());
                return context.acquireToken(resource, credential, null);
            }
        },
        PFX_FILE_AND_PFX_PASSWORD {
            @Override
            Future<AuthenticationResult> acquireToken(AzureKeyVaultCredentialProperties properties,
                AuthenticationContext context, String resource) {
                try (InputStream pfxStream = FileLoader
                    .getInputStreamFromFile(properties.getClientPfxFile())) {
                    final AsymmetricKeyCredential credential = AsymmetricKeyCredential.create(
                        properties.getClientId(), pfxStream, properties.getClientPfxPassword());
                    return context.acquireToken(resource, credential, null);
                } catch (GeneralSecurityException | IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        },
        PUBLIC_CERTIFICATE_AND_PRIVATE_KEY {
            @Override
            Future<AuthenticationResult> acquireToken(AzureKeyVaultCredentialProperties properties,
                AuthenticationContext context, String resource) {
                final PrivateKey privateKey = CertificateLoader
                    .getPrivateKey(properties.getClientPrivateKey());
                final X509Certificate x509Certificate = CertificateLoader
                    .getPublicCertificate(properties.getClientPublicCertificate());
                final AsymmetricKeyCredential credential = AsymmetricKeyCredential.create(
                    properties.getClientId(), privateKey, x509Certificate);
                return context.acquireToken(resource, credential, null);
            }
        };


        static AuthenticationType getFromProperties(AzureKeyVaultCredentialProperties properties) {
            if (StringUtils.isNotBlank(properties.getClientPfxFile())
                && StringUtils.isNotBlank(properties.getClientPfxPassword())) {
                return AuthenticationType.PFX_FILE_AND_PFX_PASSWORD;
            } else if (StringUtils.isNotBlank(properties.getClientPublicCertificate())
                && StringUtils.isNotBlank(properties.getClientPrivateKey())) {
                return AuthenticationType.PUBLIC_CERTIFICATE_AND_PRIVATE_KEY;
            } else {
                return AuthenticationType.CLIENT_KEY;
            }
        }

        abstract Future<AuthenticationResult> acquireToken(
            AzureKeyVaultCredentialProperties properties,
            AuthenticationContext context,
            String resource);
    }

}
