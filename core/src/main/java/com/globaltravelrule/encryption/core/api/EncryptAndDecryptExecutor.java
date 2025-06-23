/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:20
 */

package com.globaltravelrule.encryption.core.api;

import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptAndDecryptOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;

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
    default EncryptionKeyPair generateKeyPair() throws EncryptionException {
        throw new EncryptionException("Not supported");
    }

    /**
     * Encrypts the given plaintext using the specified encryption method.
     *
     * @param options   the encryption and decryption options
     * @param plaintext the plaintext to be encrypted
     * @return the base64 encrypted ciphertext (base64)
     */
    default String encrypt(EncryptAndDecryptOptions options, String plaintext) throws EncryptionException {
        return plaintext;
    }

    /**
     * Decrypts the given ciphertext using the specified encryption method.
     *
     * @param options          the encryption and decryption options
     * @param base64Ciphertext the base64 ciphertext to be decrypted (base64)
     * @return the decrypted plaintext (base64)
     */
    default String decrypt(EncryptAndDecryptOptions options, String base64Ciphertext) throws EncryptionException {
        return base64Ciphertext;
    }
}
