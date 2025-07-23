/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/7/23 08:26
 */

package com.globaltravelrule.encryption.core.options;

/**
 * Encrypted Params
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class KeyInfo {

    private String publicKey;

    private String privateKey;

    public KeyInfo() {
    }

    public KeyInfo(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
