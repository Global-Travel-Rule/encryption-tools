/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:20
 */

package com.globaltravelrule.encryption.core.enums;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Enum for Encryption Key Format
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public enum EncryptionKeyFormat {

    DEFAULT("DEFAULT_FORMAT", "default"),
    X509("X509_FORMAT", "x509");

    private static final Map<String, EncryptionKeyFormat> MAP;

    static {
        MAP = Arrays.stream(EncryptionKeyFormat.values()).collect(Collectors.toMap(EncryptionKeyFormat::getFormat, format -> format));
    }

    private final String format;

    private final String description;

    EncryptionKeyFormat(String name, String description) {
        this.format = name;
        this.description = description;
    }

    public String getFormat() {
        return format;
    }

    public String getDescription() {
        return description;
    }

    public static EncryptionKeyFormat parse(String algorithmType) {
        return MAP.get(algorithmType);
    }
}
