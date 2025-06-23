/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 13:07
 */

package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import org.junit.Test;

public class RsaOaepSha1Mgf1Test extends BaseTest{

    @Test
    public void testEncryptAndDecrypt() {
        doTestEncryptAndDecrypt(EncryptionAlgorithm.RSA_OAEP_SHA1_MFG1);
    }
}
