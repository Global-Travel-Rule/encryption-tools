/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:20
 */

package com.globaltravelrule.encryption.core.options;

import java.io.Serializable;

/**
 * encryption and decryption base options
 */
public class BaseOptions implements Serializable {

    /**
     * algorithm type
     */
    private String algorithm;

    /**
     * encrypt format (full,partial)
     */
    private String encryptFormat;

    public BaseOptions() {

    }

    public BaseOptions(String algorithm) {
        this.algorithm = algorithm;
    }

    public BaseOptions(String algorithm, String encryptFormat) {
        this.algorithm = algorithm;
        this.encryptFormat = encryptFormat;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getEncryptFormat() {
        return encryptFormat;
    }

    public void setEncryptFormat(String encryptFormat) {
        this.encryptFormat = encryptFormat;
    }
}
