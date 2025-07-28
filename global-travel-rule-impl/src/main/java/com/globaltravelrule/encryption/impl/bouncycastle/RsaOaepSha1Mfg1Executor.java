/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.globaltravelrule.encryption.core.api.EncryptAndDecryptExecutor;
import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.enums.EncryptionKeyFormat;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;
import com.globaltravelrule.encryption.impl.bouncycastle.utils.CryptoUtils;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * rsa oaep sha1 mfg1 executor
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class RsaOaepSha1Mfg1Executor implements EncryptAndDecryptExecutor {

    private static final int GCM_TAG_BIT_LENGTH = 128;
    private static final int GCM_IV_BIT_LENGTH = 128;
    private static final int AES_GCM_KEY_BIT_LENGTH = 256;
    private static final int KEY_SIZE = 2048;
    private static final int PER_NONCE_SIZE = 8;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public EncryptionAlgorithm getCryptionAlgorithm() {
        return EncryptionAlgorithm.RSA_OAEP_SHA1_MFG1;
    }

    @Override
    public EncryptionKeyPair generateKeyPair(GenerateKeyPairOptions options) throws EncryptionException {
        try {
            BigInteger publicExponent = BigInteger.valueOf(65537);
            SecureRandom random = new SecureRandom();
            RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
            generator.init(new RSAKeyGenerationParameters(
                    publicExponent,
                    random,
                    KEY_SIZE,
                    80
            ));
            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
            if (EncryptionKeyFormat.X509.getFormat().equals(options.getKeyFormat())) {
                // Convert to SubjectPublicKeyInfo
                RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
                SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                        PKCSObjectIdentifiers.rsaEncryption,
                        org.bouncycastle.asn1.DERNull.INSTANCE
                ), new org.bouncycastle.asn1.pkcs.RSAPublicKey(publicKey.getModulus(), publicKey.getExponent()));

                RSAPrivateCrtKeyParameters bcPrivateKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
                return new EncryptionKeyPair(
                        CryptoUtils.publicKeyToX509PEM(options,
                                subjectPublicKeyInfo,
                                new BcRSAContentSignerBuilder(
                                        new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption),
                                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)).build(bcPrivateKey)),
                        CryptoUtils.privateKeyToPEM(convertToPrivateKey((RSAPrivateCrtKeyParameters) keyPair.getPrivate())));
            } else {
                return new EncryptionKeyPair(
                        CryptoUtils.publicKeyToPEM(convertToPublicKey((RSAKeyParameters) keyPair.getPublic())),
                        CryptoUtils.privateKeyToPEM(convertToPrivateKey((RSAPrivateCrtKeyParameters) keyPair.getPrivate()))
                );
            }
        } catch (Exception ex) {
            throw new EncryptionException("generate key RSA pair failed", ex);
        }
    }

    public static PublicKey convertToPublicKey(RSAKeyParameters publicKey) throws Exception {
        if (publicKey.isPrivate()) {
            throw new IllegalArgumentException("The RSAKeyParameters provided are not public keys");
        }
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
                publicKey.getModulus(),
                publicKey.getExponent()
        );
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private PrivateKey convertToPrivateKey(RSAPrivateCrtKeyParameters bcPrivateKey) throws Exception {
        // 1. Create RSA Private Key Specification
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                bcPrivateKey.getModulus(),           // n
                bcPrivateKey.getPublicExponent(),    // e
                bcPrivateKey.getExponent(),          // d
                bcPrivateKey.getP(),                 // p
                bcPrivateKey.getQ(),                 // q
                bcPrivateKey.getDP(),                // dP
                bcPrivateKey.getDQ(),                // dQ
                bcPrivateKey.getQInv()               // qInv
        );

        // 2. Use KeyFactory for conversion
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    @Override
    public String encrypt(EncryptionAndDecryptionOptions options) {
        try {
            if (options.getRawPayload() == null || options.getRawPayload().isEmpty()) {
                return options.getRawPayload();
            }

            Map<String, String> headerMap = new HashMap<>();
            headerMap.put("enc", "A256GCM");
            headerMap.put("alg", "RSA-OAEP");
            String header = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsString(headerMap).getBytes());
            SecretKeySpec aesKeySpec = new SecretKeySpec(nonce(AES_GCM_KEY_BIT_LENGTH), "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, nonce(GCM_IV_BIT_LENGTH));
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, gcmParameterSpec);
            aesCipher.updateAAD(header.getBytes());
            byte[] encryptedMessageFromPayload = aesCipher.doFinal(options.getRawPayload().getBytes(StandardCharsets.UTF_8));

            int tagPosition = encryptedMessageFromPayload.length - (GCM_TAG_BIT_LENGTH / 8);
            byte[] cipherTextBytes = CryptoUtils.subtractArray(encryptedMessageFromPayload, 0, tagPosition);
            byte[] gcmTagBytes = CryptoUtils.subtractArray(encryptedMessageFromPayload, tagPosition, (GCM_TAG_BIT_LENGTH / 8));
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("OAEP");
            algParams.init(new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            RSAPublicKey publicKey = (RSAPublicKey) CryptoUtils.pemToPublicKey(options.getReceiverKeyInfo().getPublicKey());
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, algParams);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKeySpec.getEncoded());

            String encodedEncryptedAesKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedAesKey);
            String encodedIV = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(gcmParameterSpec.getIV());
            String encodedCipherText = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(cipherTextBytes);
            String encodedGcmTag = java.util.Base64.
                    getUrlEncoder().withoutPadding().encodeToString(gcmTagBytes);

            return String.format("%s.%s.%s.%s.%s",
                    header,
                    encodedEncryptedAesKey,
                    encodedIV,
                    encodedCipherText,
                    encodedGcmTag);
        } catch (Exception ex) {
            throw new EncryptionException("Failed to encrypt data by AES GCM with RSA OAEP using SHA-1 and MGF1 padding", ex);
        }
    }

    @Override
    public String decrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        try {
            if (options.getSecuredPayload() == null || options.getSecuredPayload().isEmpty()) {
                return options.getSecuredPayload();
            }

            String[] parts = options.getSecuredPayload().split("\\.");
            String header = parts[0];

            byte[] encryptedAesKey = java.util.Base64.getUrlDecoder().decode(parts[1]);
            byte[] iv = java.util.Base64.getUrlDecoder().decode(parts[2]);
            byte[] cipherText = java.util.Base64.getUrlDecoder().decode(parts[3]);
            byte[] gcmTag = java.util.Base64.getUrlDecoder().decode(parts[4]);

            AlgorithmParameters algParams = AlgorithmParameters.getInstance("OAEP");
            algParams.init(new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            RSAPrivateKey privateKey = (RSAPrivateKey) CryptoUtils.pemToPrivateKey(options.getReceiverKeyInfo().getPrivateKey());
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, algParams);
            byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

            SecretKeySpec aesKeySpec = new SecretKeySpec(decryptedAesKey, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_IV_BIT_LENGTH, iv); //{128, 120, 112, 104, 96
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, gcmParameterSpec);
            aesCipher.updateAAD(header.getBytes());

            return new String(aesCipher.doFinal(CryptoUtils.concatArray(cipherText, gcmTag)), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new EncryptionException("Failed to decrypt data by AES GCM with RSA OAEP using SHA-1 and MFG1 padding", ex);
        }
    }

    private byte[] nonce(int size) {
        byte[] randomBytes = new byte[size / PER_NONCE_SIZE];
        new Random().nextBytes(randomBytes);
        return randomBytes;
    }
}
