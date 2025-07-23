package com.globaltravelrule.encryption.core.options.metadata;


/**
 * ECIES Algorithm Meta Info
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class ECIESInfo {

    /**
     * base64 format key string
     */
    private String ephemeralPublicKey;

    public ECIESInfo() {
    }

    public ECIESInfo(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }
}
