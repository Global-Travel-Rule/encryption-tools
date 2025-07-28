/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;
import com.globaltravelrule.encryption.impl.bouncycastle.enums.CurveType;

/**
 * ecies p256 executor
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class EciesSect571k1Executor extends EciesExecutor {

    @Override
    public EncryptionAlgorithm getCryptionAlgorithm() {
        return EncryptionAlgorithm.ECIES_SECT571K1;
    }

    @Override
    public EncryptionKeyPair generateKeyPair(GenerateKeyPairOptions options) throws EncryptionException {
        return doGenerateKeyPair(options, CurveType.SECT571K1);
    }

    @Override
    public String encrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        return encrypt(options, CurveType.SECT571K1);
    }

    @Override
    public String decrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        return decrypt(options, CurveType.SECT571K1);
    }
}
