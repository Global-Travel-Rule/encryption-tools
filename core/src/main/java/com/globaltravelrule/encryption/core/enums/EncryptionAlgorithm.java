/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:20
 */

package com.globaltravelrule.encryption.core.enums;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Encryption algorithm enum.
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.0
 */
public enum EncryptionAlgorithm {
    ED25519_CURVE25519("ed25519_curve25519", "ed25519 with curve25519 cipher"),
    KECCAK256("keccak256", "keccak256 hash with salt"),
    RSA_OAEP_SHA1_MFG1("rsa_ecb_oaep_with_sha1_and_mgf1padding", "rsa ecb oaep with sha1 and mgf1 padding encryption"),
    ECIES_SECP256R1("ecies_secp256r1", "ecies_secp256r1 encryption"),
    ECIES_SECP384R1("ecies_secp384r1", "ecies_secp384r1 encryption"),
    ECIES_SECP521R1("ecies_secp521r1", "ecies_secp521r1 encryption"),
    ECIES_SECP256K1("ecies_secp256k1", "ecies_secp256k1 encryption"),
    ECIES_SECT571K1("ecies_sect571k1", "ecies_sect571k1 encryption"),
    ECIES_SECP384R1_TUBITAK("ecies_secp384r1_tubitak", "ecies_secp384r1_tubitak encryption");

    private static final Map<String, EncryptionAlgorithm> MAP;

    static {
        MAP = Arrays.stream(EncryptionAlgorithm.values()).collect(Collectors.toMap(EncryptionAlgorithm::getName, algorithm -> algorithm));
    }

    private final String name;

    private final String description;

    EncryptionAlgorithm(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public static EncryptionAlgorithm parse(String algorithmType) {
        return MAP.get(algorithmType);
    }
}
