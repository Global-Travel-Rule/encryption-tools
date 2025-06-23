/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:20
 */

package com.globaltravelrule.encryption.core.options;

/**
 * Options for encryption and decryption.
 */
public class EncryptAndDecryptOptions extends BaseOptions {

    /**
     * encryption public key (Message transmission destination)
     */
    private String base64RemotePublicKey;

    /**
     * decryption private key (Message transmission source)
     */
    private String base64HostedPrivateKey;

    /***
     * salt for hash encryption
     */
    private String salt;

    public EncryptAndDecryptOptions() {
        super();
    }

    public EncryptAndDecryptOptions(String algorithm) {
        super(algorithm);
    }

    public EncryptAndDecryptOptions(String algorithm, String encryptFormat, String base64RemotePublicKey, String base64HostedPrivateKey) {
        super(algorithm, encryptFormat);
        this.base64RemotePublicKey = base64RemotePublicKey;
        this.base64HostedPrivateKey = base64HostedPrivateKey;
    }

    public EncryptAndDecryptOptions(String algorithm, String base64RemotePublicKey, String base64HostedPrivateKey, String salt, String encryptFormat) {
        super(algorithm, encryptFormat);
        this.base64RemotePublicKey = base64RemotePublicKey;
        this.base64HostedPrivateKey = base64HostedPrivateKey;
        this.salt = salt;
    }

    public String getBase64RemotePublicKey() {
        return base64RemotePublicKey;
    }

    public void setBase64RemotePublicKey(String base64RemotePublicKey) {
        this.base64RemotePublicKey = base64RemotePublicKey;
    }

    public String getBase64HostedPrivateKey() {
        return base64HostedPrivateKey;
    }

    public void setBase64HostedPrivateKey(String base64HostedPrivateKey) {
        this.base64HostedPrivateKey = base64HostedPrivateKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
