/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:20
 */

package com.globaltravelrule.encryption.core.api;

import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;

/**
 * Encrypt and decrypt algorithm method.
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public interface EncryptAndDecryptExecutor {

    /**
     * Get the encryption algorithm registration enum.
     *
     * @return the encryption algorithm
     */
    EncryptionAlgorithm getCryptionAlgorithm();

    /**
     * Generate a key pair for encryption and decryption.
     *
     * @return the key pair
     * @throws EncryptionException if an error occurs during key pair generation
     */
    default EncryptionKeyPair generateKeyPair(GenerateKeyPairOptions options) throws EncryptionException {
        throw new EncryptionException("Not supported");
    }

    /**
     * Encrypts the given plaintext using the specified encryption method.
     *
     * @param options the encryption and decryption options
     * @return processed PiiSecuredInfo with base64 encrypted ciphertext
     */
    default String encrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        throw new EncryptionException("Not supported");
    }

    /**
     * Decrypts the given ciphertext using the specified encryption method.
     *
     * @param options the encryption and decryption options with base64 encrypted ciphertext
     * @return processed PiiSecuredInfo with plaintext
     */
    default String decrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        throw new EncryptionException("Not supported");
    }
}
