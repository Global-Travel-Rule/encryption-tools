/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */
package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.api.EncryptAndDecryptExecutor;
import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

/**
 * Keccak256 Hash Calculator
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class Keccak256HashExecutor implements EncryptAndDecryptExecutor {

    @Override
    public EncryptionAlgorithm getCryptionAlgorithm() {
        return EncryptionAlgorithm.KECCAK256;
    }

    /**
     * Calculate the Keccak-256 hash value of the input data
     */
    @Override
    public String encrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        if (options.getRawPayload() == null || options.getRawPayload().isEmpty()) {
            return options.getRawPayload();
        }

        // Create Keccak-256 Abstract Instance (256 bit Output)
        KeccakDigest keccak = new KeccakDigest(256);

        // Update input data
        String combined = options.getRawPayload() + options.getEncryptionParams().getKeccak256().getSalt();
        byte[] data = combined.getBytes(StandardCharsets.UTF_8);
        keccak.update(data, 0, data.length);

        // Prepare output buffer
        byte[] output = new byte[keccak.getDigestSize()];

        // Calculate Hash
        keccak.doFinal(output, 0);

        // return base64 string
        return Base64.toBase64String(output);
    }
}
