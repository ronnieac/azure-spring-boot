/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.keyvault.spring;

import com.microsoft.azure.utils.PropertyLoader;

public class Constants {
    public static final String AZURE_KEYVAULT_USER_AGENT = "spring-boot-starter/" + PropertyLoader.getProjectVersion();
    public static final String AZURE_CLIENTID = "azure.keyvault.client-id";
    public static final String AZURE_CLIENT_PFX_FILE = "azure.keyvault.client-pfx-file";
    public static final String AZURE_CLIENT_PFX_PASSWORD = "azure.keyvault.client-pfx-password";
    public static final String AZURE_CLIENT_PUBLIC_CERTIFICATE = "azure.keyvault.client-public-certificate";
    public static final String AZURE_CLIENT_PRIVATE_KEY = "azure.keyvault.client-private-key";
    public static final String AZURE_CLIENTKEY = "azure.keyvault.client-key";
    public static final String AZURE_KEYVAULT_ENABLED = "azure.keyvault.enabled";
    public static final String AZURE_KEYVAULT_VAULT_URI = "azure.keyvault.uri";
    public static final String AZURE_KEYVAULT_REFRESH_INTERVAL = "azure.keyvault.refresh-interval";
    public static final String AZURE_KEYVAULT_PROPERTYSOURCE_NAME = "azurekv";
    public static final String AZURE_TOKEN_ACQUIRE_TIMEOUT_IN_SECONDS = "azure.keyvault.token-acquire-timeout-seconds";
    public static final String AZURE_KEYVAULT_ALLOW_TELEMETRY = "azure.keyvault.allow.telemetry";

    public static final long DEFAULT_REFRESH_INTERVAL_MS = 1800000L;
    public static final long TOKEN_ACQUIRE_TIMEOUT_SECS = 60L;
}
