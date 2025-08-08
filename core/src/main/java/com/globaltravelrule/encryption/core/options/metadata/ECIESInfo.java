package com.globaltravelrule.encryption.core.options.metadata;


import java.security.KeyPair;

/**
 * ECIES Algorithm Meta Info
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class ECIESInfo {

    /**
     * Used for caching dynamic key context during encryption process,
     * corresponding to recursive field scenarios, using a unified temporary keypair
     *
     */
    private KeyPair ephemeralKP;

    /**
     * base64 format key string
     */
    private String ephemeralPublicKey;

    public ECIESInfo() {
    }

    public ECIESInfo(KeyPair ephemeralKP) {
        this.ephemeralKP = ephemeralKP;
    }

    public ECIESInfo(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public ECIESInfo(KeyPair ephemeralKP, String ephemeralPublicKey) {
        this.ephemeralKP = ephemeralKP;
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public KeyPair getEphemeralKP() {
        return ephemeralKP;
    }

    public void setEphemeralKP(KeyPair ephemeralKP) {
        this.ephemeralKP = ephemeralKP;
    }

    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }
}
