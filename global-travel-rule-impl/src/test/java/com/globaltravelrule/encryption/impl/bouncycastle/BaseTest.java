/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/19 19:23
 */

package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.EncryptionUtils;
import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.enums.EncryptionFormat;
import com.globaltravelrule.encryption.core.enums.EncryptionKeyFormat;
import com.globaltravelrule.encryption.core.options.*;
import com.globaltravelrule.encryption.core.options.metadata.Keccak256Info;
import org.bouncycastle.util.encoders.Base64;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

public class BaseTest {

    public static final List<String> HASH_ALGORITHMS = List.of(EncryptionAlgorithm.KECCAK256.getName());

    public static final List<String> NORMAL_ALGORITHMS = List.of(
            EncryptionAlgorithm.ED25519_CURVE25519.getName(),
            EncryptionAlgorithm.RSA_OAEP_SHA1_MFG1.getName(),
            EncryptionAlgorithm.ECIES_SECP256R1.getName(),
            EncryptionAlgorithm.ECIES_SECP384R1.getName(),
            EncryptionAlgorithm.ECIES_SECP521R1.getName(),
            EncryptionAlgorithm.ECIES_SECP256K1.getName(),
            EncryptionAlgorithm.ECIES_SECT571K1.getName());

    public void doTestEncryptAndDecrypt(EncryptionAlgorithm algorithm) {
        System.out.println("------ start encrypt and decrypt for:" + algorithm.getName());

        String originalMessage = "{\"test_num1\":0,\"test_num2\":1.01,\"test_bool\":true,\"test_string\":\"testing\",\"testing_object\":{\"testing_object_num1\":0,\"testing_object_num2\":1.01,\"testing_object_bool\":true,\"testing_object_string\":\"testing\"}}";
        System.out.println("raw message: " + originalMessage);

        PiiSecuredInfo piiSecuredInfo = new PiiSecuredInfo();
        piiSecuredInfo.setSecretAlgorithm(algorithm.getName());

        if (HASH_ALGORITHMS.contains(algorithm.getName())) {
            int saltSize = 16;
            // 1. Generate salt
            byte[] saltData = new byte[saltSize];
            new SecureRandom().nextBytes(saltData);
            String salt = Base64.toBase64String(saltData);
            EncryptionParams params = new EncryptionParams();
            params.setKeccak256(new Keccak256Info(salt));
            piiSecuredInfo.setEncryptionParams(params);
            piiSecuredInfo.setPiiSecretFormatType(EncryptionFormat.JSON_FIELD_HASHED.getFormat());
            piiSecuredInfo.setSecuredPayload(null);
            doTestEncryptAndDecryptByDifferentMessageFormat(piiSecuredInfo, originalMessage);
        }

        if (NORMAL_ALGORITHMS.contains(algorithm.getName())) {
            // 1. Generate key pair
            GenerateKeyPairOptions options = new GenerateKeyPairOptions(algorithm.getName());
            options.setKeyFormat(EncryptionKeyFormat.X509.getFormat());
            options.setSubjectDN("CN=Global Travel Rule,SERIALNUMBER=00001");
            Date startDate = new Date();
            Instant instant = startDate.toInstant();
            LocalDateTime dateTime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            LocalDateTime endDateTime = dateTime.plusYears(10);
            Date endDate = Date.from(endDateTime.atZone(ZoneId.systemDefault()).toInstant());
            options.setStartDate(startDate);
            options.setEndDate(endDate);

            EncryptionKeyPair aliceKp = EncryptionUtils.generateEncryptionKeyPair(options);
            EncryptionKeyPair bobKp = EncryptionUtils.generateEncryptionKeyPair(options);
            System.out.println("alice key pair: " + aliceKp.getPublicKey() + ", " + aliceKp.getPrivateKey());
            System.out.println("bob key pair: " + bobKp.getPublicKey() + ", " + bobKp.getPrivateKey());

            piiSecuredInfo.setInitiatorKeyInfo(new KeyInfo(aliceKp.getPublicKey(), aliceKp.getPrivateKey()));
            piiSecuredInfo.setReceiverKeyInfo(new KeyInfo(bobKp.getPublicKey(), bobKp.getPrivateKey()));
            piiSecuredInfo.setPiiSecretFormatType(EncryptionFormat.FULL_JSON_OBJECT_ENCRYPT.getFormat());
            piiSecuredInfo.setSecuredPayload(null);
            doTestEncryptAndDecryptByDifferentMessageFormat(piiSecuredInfo, originalMessage);

            piiSecuredInfo.setInitiatorKeyInfo(new KeyInfo(aliceKp.getPublicKey(), aliceKp.getPrivateKey()));
            piiSecuredInfo.setReceiverKeyInfo(new KeyInfo(bobKp.getPublicKey(), bobKp.getPrivateKey()));
            piiSecuredInfo.setPiiSecretFormatType(EncryptionFormat.JSON_FIELD_ENCRYPT.getFormat());
            piiSecuredInfo.setSecuredPayload(null);
            doTestEncryptAndDecryptByDifferentMessageFormat(piiSecuredInfo, originalMessage);
        }
        System.out.println("------ end encrypt and decrypt for:" + algorithm.getName());
    }

    private void doTestEncryptAndDecryptByDifferentMessageFormat(PiiSecuredInfo piiSecuredInfo, String rawPayload) {
        if (EncryptionAlgorithm.KECCAK256.getName().equals(piiSecuredInfo.getSecretAlgorithm())) {
            String sendHashedMessage = EncryptionUtils.encrypt(piiSecuredInfo, rawPayload).getSecuredPayload();
            System.out.printf("sender hashed message(%s): %s%n", piiSecuredInfo.getPiiSecretFormatType(), piiSecuredInfo.getSecuredPayload());

            String receiverHashedMessage = EncryptionUtils.encrypt(piiSecuredInfo, rawPayload).getSecuredPayload();
            System.out.printf("receiver hashed message(%s): %s%n", piiSecuredInfo.getPiiSecretFormatType(), receiverHashedMessage);

            assert sendHashedMessage.equals(receiverHashedMessage);
        } else {
            String encryptedMessage = EncryptionUtils.encrypt(piiSecuredInfo, rawPayload).getSecuredPayload();
            System.out.printf("sender encrypted message(%s): %s%n", piiSecuredInfo.getPiiSecretFormatType(), encryptedMessage);

            String decryptedMessage = EncryptionUtils.decrypt(piiSecuredInfo);
            System.out.println("decrypted message: " + decryptedMessage);

            assert rawPayload.equals(decryptedMessage);
        }
    }
}
