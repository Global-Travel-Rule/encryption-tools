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
import com.globaltravelrule.encryption.core.options.EncryptAndDecryptOptions;
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
    public String encrypt(EncryptAndDecryptOptions options, String plaintext) throws EncryptionException {
        if (plaintext == null || plaintext.isEmpty()){
            return plaintext;
        }

        // 创建Keccak-256摘要实例(256位输出)
        KeccakDigest keccak = new KeccakDigest(256);

        // 更新输入数据
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        keccak.update(data, 0, data.length);

        // 准备输出缓冲区
        byte[] output = new byte[keccak.getDigestSize()];

        // 计算哈希
        keccak.doFinal(output, 0);

        // 返回base64字符串
        return Base64.toBase64String(output);
    }
}
