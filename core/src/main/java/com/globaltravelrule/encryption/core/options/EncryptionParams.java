/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/7/23 08:25
 */

package com.globaltravelrule.encryption.core.options;


import com.globaltravelrule.encryption.core.options.metadata.Curve25519Info;
import com.globaltravelrule.encryption.core.options.metadata.ECIESInfo;
import com.globaltravelrule.encryption.core.options.metadata.Keccak256Info;
import com.globaltravelrule.encryption.core.options.metadata.RSAInfo;

/**
 * Encrypted Params
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class EncryptionParams {

    private Curve25519Info curve25519;

    private RSAInfo rsa;

    private ECIESInfo ecies;

    private Keccak256Info keccak256;

    public Curve25519Info getCurve25519() {
        return curve25519;
    }

    public void setCurve25519(Curve25519Info curve25519) {
        this.curve25519 = curve25519;
    }

    public RSAInfo getRsa() {
        return rsa;
    }

    public void setRsa(RSAInfo rsa) {
        this.rsa = rsa;
    }

    public ECIESInfo getEcies() {
        return ecies;
    }

    public void setEcies(ECIESInfo ecies) {
        this.ecies = ecies;
    }

    public Keccak256Info getKeccak256() {
        return keccak256;
    }

    public void setKeccak256(Keccak256Info keccak256) {
        this.keccak256 = keccak256;
    }
}
