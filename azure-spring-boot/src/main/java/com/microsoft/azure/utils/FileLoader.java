/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

public interface FileLoader {

    static InputStream getInputStreamFromFileSystem(final String filename) {
        try {
            final File file = new File(filename);
            return new FileInputStream(file);
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        }
    }

    static InputStream getInputStreamFromClasspath(final String filename) {
        try {
            final Resource classpathResource = new ClassPathResource(filename);
            return classpathResource.getInputStream();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    static InputStream getInputStreamFromFile(final String filename) {
        final String classpathPrefix = "classpath://";
        if (filename.startsWith(classpathPrefix)) {
            return getInputStreamFromClasspath(filename.replaceFirst(classpathPrefix, ""));
        } else {
            return getInputStreamFromFileSystem(filename);
        }
    }

    static byte[] getAllBytesFromFile(final String filename) {
        try (InputStream inputStream = getInputStreamFromFile(filename)) {
            final byte[] keyBytes = IOUtils.toByteArray(inputStream);
            inputStream.close();
            return keyBytes;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
