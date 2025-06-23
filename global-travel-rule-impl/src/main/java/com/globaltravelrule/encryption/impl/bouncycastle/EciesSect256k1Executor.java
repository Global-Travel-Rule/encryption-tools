/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptAndDecryptOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.impl.bouncycastle.enums.CurveType;

/**
 * ecies p256 executor
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class EciesSect256k1Executor extends EciesExecutor {

    @Override
    public EncryptionAlgorithm getCryptionAlgorithm() {
        return EncryptionAlgorithm.ECIES_SECP256K1;
    }

    @Override
    public EncryptionKeyPair generateKeyPair() throws EncryptionException {
        return doGenerateKeyPair(CurveType.SECT256K1);
    }

    @Override
    public String encrypt(EncryptAndDecryptOptions options, String plaintext) throws EncryptionException {
        return encrypt(options.getBase64RemotePublicKey(), plaintext, CurveType.SECT256K1);
    }

    @Override
    public String decrypt(EncryptAndDecryptOptions options, String base64Ciphertext) throws EncryptionException {
        return decrypt(options.getBase64HostedPrivateKey(), base64Ciphertext, CurveType.SECT256K1);
    }
}
