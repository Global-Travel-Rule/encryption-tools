/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/7/23 10:20
 */

package com.globaltravelrule.encryption.core.options;

/**
 * Encrypt and decrypt parameter class,
 * using unified encryption and decryption methods to call
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class EncryptionAndDecryptionOptions {

    private KeyInfo initiatorKeyInfo;

    private KeyInfo receiverKeyInfo;

    /**
     * @see com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm
     */
    private String algorithmType;

    /**
     * @see com.globaltravelrule.encryption.core.enums.EncryptionFormat
     */
    private String encryptionFormatType;

    private EncryptionParams encryptionParams;

    private String securedPayload;

    private String rawPayload;

    public EncryptionAndDecryptionOptions() {

    }

    public EncryptionAndDecryptionOptions(KeyInfo initiatorKeyInfo, KeyInfo receiverKeyInfo, String algorithmType, String encryptionFormatType) {
        this.initiatorKeyInfo = initiatorKeyInfo;
        this.receiverKeyInfo = receiverKeyInfo;
        this.algorithmType = algorithmType;
        this.encryptionFormatType = encryptionFormatType;
    }

    public static EncryptionAndDecryptionOptions withPiiSecuredInfo(PiiSecuredInfo piiSecuredInfo) {
        EncryptionAndDecryptionOptions options = new EncryptionAndDecryptionOptions(
                piiSecuredInfo.getInitiatorKeyInfo(),
                piiSecuredInfo.getReceiverKeyInfo(),
                piiSecuredInfo.getSecretAlgorithm(),
                piiSecuredInfo.getPiiSecretFormatType()
        );
        options.setEncryptionParams(piiSecuredInfo.getEncryptionParams());
        options.setSecuredPayload(piiSecuredInfo.getSecuredPayload());
        return options;
    }

    public KeyInfo getInitiatorKeyInfo() {
        return initiatorKeyInfo;
    }

    public KeyInfo getReceiverKeyInfo() {
        return receiverKeyInfo;
    }


    public String getAlgorithmType() {
        return algorithmType;
    }

    public String getEncryptionFormatType() {
        return encryptionFormatType;
    }

    public EncryptionParams getEncryptionParams() {
        return encryptionParams;
    }

    public void setEncryptionParams(EncryptionParams encryptionParams) {
        this.encryptionParams = encryptionParams;
    }

    public String getSecuredPayload() {
        return securedPayload;
    }

    public void setSecuredPayload(String securedPayload) {
        this.securedPayload = securedPayload;
    }

    public String getRawPayload() {
        return rawPayload;
    }

    public void setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
    }
}