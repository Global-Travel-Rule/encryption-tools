/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle.enums;


/**
 * Enum representing different curve types.
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public enum CurveType {

    // NIST Standard Curve
    SECP256R1("secp256r1", "ECIESwithAES256-CBC/HMAC-SHA256"),
    SECP384R1("secp384r1", "ECIESwithAES256-CBC/HMAC-SHA384"),
    SECP521R1("secp521r1", "ECIESwithAES256-CBC/HMAC-SHA512"),

    // SEC/Koblitz Curve
    SECT256K1("secp256k1", "ECIESwithAES256-CBC/HMAC-SHA256"),
    SECT571K1("sect571k1", "ECIESwithAES256-CBC/HMAC-SHA512");

    private final String curveName;

    private final String algorithm;

    CurveType(String curveName,String algorithm) {
        this.curveName = curveName;
        this.algorithm = algorithm;
    }

    public String getCurveName() {
        return curveName;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}