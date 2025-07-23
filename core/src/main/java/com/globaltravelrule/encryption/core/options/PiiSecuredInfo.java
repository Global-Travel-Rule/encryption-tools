/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/7/23 08:26
 */

package com.globaltravelrule.encryption.core.options;

/**
 * Encrypted PII Information
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class PiiSecuredInfo {

    private KeyInfo initiatorKeyInfo;

    private KeyInfo receiverKeyInfo;

    /**
     * @see com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm
     */
    private String secretAlgorithm;

    /**
     * @see com.globaltravelrule.encryption.core.enums.EncryptionFormat
     */
    private String piiSecretFormatType;

    private EncryptionParams encryptionParams;

    private String piiSpecVersion;

    private String securedPayload;

    public PiiSecuredInfo() {
    }

    public KeyInfo getInitiatorKeyInfo() {
        return initiatorKeyInfo;
    }

    public void setInitiatorKeyInfo(KeyInfo initiatorKeyInfo) {
        this.initiatorKeyInfo = initiatorKeyInfo;
    }

    public KeyInfo getReceiverKeyInfo() {
        return receiverKeyInfo;
    }

    public void setReceiverKeyInfo(KeyInfo receiverKeyInfo) {
        this.receiverKeyInfo = receiverKeyInfo;
    }

    public String getSecretAlgorithm() {
        return secretAlgorithm;
    }

    public void setSecretAlgorithm(String secretAlgorithm) {
        this.secretAlgorithm = secretAlgorithm;
    }

    public String getPiiSecretFormatType() {
        return piiSecretFormatType;
    }

    public void setPiiSecretFormatType(String piiSecretFormatType) {
        this.piiSecretFormatType = piiSecretFormatType;
    }

    public EncryptionParams getEncryptionParams() {
        return encryptionParams;
    }

    public void setEncryptionParams(EncryptionParams encryptionParams) {
        this.encryptionParams = encryptionParams;
    }

    public String getPiiSpecVersion() {
        return piiSpecVersion;
    }

    public void setPiiSpecVersion(String piiSpecVersion) {
        this.piiSpecVersion = piiSpecVersion;
    }

    public String getSecuredPayload() {
        return securedPayload;
    }

    public void setSecuredPayload(String securedPayload) {
        this.securedPayload = securedPayload;
    }
}
