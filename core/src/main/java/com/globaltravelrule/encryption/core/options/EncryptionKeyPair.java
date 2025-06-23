/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/12 08:30
 */

package com.globaltravelrule.encryption.core.options;

import java.io.Serializable;

/**
 * encryption key pair
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class EncryptionKeyPair implements Serializable {

    // base64 public key
    private String base64PublicKey;

    // base64 private key
    private String base64privateKey;

    // random salt
    private String salt;

    public EncryptionKeyPair() {
    }

    public EncryptionKeyPair(String base64PublicKey, String base64privateKey, String salt) {
        this.base64PublicKey = base64PublicKey;
        this.base64privateKey = base64privateKey;
        this.salt = salt;
    }

    public EncryptionKeyPair(String base64PublicKey, String base64privateKey) {
        this.base64PublicKey = base64PublicKey;
        this.base64privateKey = base64privateKey;
    }

    public EncryptionKeyPair(String salt) {
        this.salt = salt;
    }

    public String getBase64PublicKey() {
        return base64PublicKey;
    }

    public void setBase64PublicKey(String base64PublicKey) {
        this.base64PublicKey = base64PublicKey;
    }

    public String getBase64privateKey() {
        return base64privateKey;
    }

    public void setBase64privateKey(String base64privateKey) {
        this.base64privateKey = base64privateKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
