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
 * Enum for Encryption Format
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public enum EncryptionFormat {

    FULL_JSON_OBJECT_ENCRYPT("FULL_JSON_OBJECT_ENCRYPT", "full"),
    JSON_FIELD_ENCRYPT("JSON_FIELD_ENCRYPT", "partial"),
    JSON_FIELD_HASHED("JSON_FIELD_HASH", "partial");

    private static final Map<String, EncryptionFormat> MAP;

    static {
        MAP = Arrays.stream(EncryptionFormat.values()).collect(Collectors.toMap(EncryptionFormat::getFormat, format -> format));
    }

    private final String format;

    private final String description;

    EncryptionFormat(String name, String description) {
        this.format = name;
        this.description = description;
    }

    public String getFormat() {
        return format;
    }

    public String getDescription() {
        return description;
    }

    public static EncryptionFormat parse(String algorithmType) {
        return MAP.get(algorithmType);
    }
}
