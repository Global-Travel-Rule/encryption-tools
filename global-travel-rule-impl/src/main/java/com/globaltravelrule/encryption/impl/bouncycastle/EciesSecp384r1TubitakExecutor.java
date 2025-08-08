/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/7/23 08:25
 */
package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.EncryptionParams;
import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;
import com.globaltravelrule.encryption.core.options.metadata.ECIESInfo;
import com.globaltravelrule.encryption.impl.bouncycastle.enums.CurveType;
import com.globaltravelrule.encryption.impl.bouncycastle.utils.CryptoUtils;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ecies p384 for TÜBİTAK executor
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class EciesSecp384r1TubitakExecutor extends EciesExecutor {

    private static final int GCM_TAG_LENGTH = 128;

    private static final int GCM_NONCE_LENGTH = 12;

    @Override
    public EncryptionAlgorithm getCryptionAlgorithm() {
        return EncryptionAlgorithm.ECIES_SECP384R1_TUBITAK;
    }

    @Override
    public EncryptionKeyPair generateKeyPair(GenerateKeyPairOptions options) throws EncryptionException {
        return doGenerateKeyPair(options, CurveType.SECP384R1);
    }

    @Override
    public String encrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        try {
            if (options.getRawPayload() == null || options.getRawPayload().isEmpty()) {
                return options.getRawPayload();
            }

            ECParameterSpec ecSpec = getECParameterSpec();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(ecSpec);

            PublicKey recipientPublicKey = CryptoUtils.pemToPublicKey(options.getReceiverKeyInfo().getPublicKey());
            PrivateKey senderPrivateKey = CryptoUtils.pemToPrivateKey(options.getInitiatorKeyInfo().getPrivateKey());

            KeyPair ephemeralKP;
            PrivateKey ephemeralPrivateKey;
            PublicKey ephemeralPublicKey;
            if (options.getEncryptionParams() != null
                    && options.getEncryptionParams().getEcies() != null
                    && options.getEncryptionParams().getEcies().getEphemeralKP() != null) {
                ephemeralKP = options.getEncryptionParams().getEcies().getEphemeralKP();
                ephemeralPrivateKey = ephemeralKP.getPrivate();
            } else {
                ephemeralKP = kpg.generateKeyPair();
                ephemeralPrivateKey = ephemeralKP.getPrivate();
                ephemeralPublicKey = ephemeralKP.getPublic();
                String sharePublicKey = Base64.toBase64String(ephemeralPublicKey.getEncoded());

                EncryptionParams encryptionParams = new EncryptionParams();
                encryptionParams.setEcies(new ECIESInfo(ephemeralKP, sharePublicKey));
                options.setEncryptionParams(encryptionParams);
            }
            // Compute shared secrets
            byte[] sharedSecret1 = ecdhSharedSecret(ephemeralPrivateKey, recipientPublicKey);
            byte[] sharedSecret2 = ecdhSharedSecret(senderPrivateKey, recipientPublicKey);

            // Derive AES key by SHA-256 of concatenated secrets
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(sharedSecret2);
            sha256.update(sharedSecret1);
            byte[] aesKey = sha256.digest();

            // Generate random nonce
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);

            // AES-GCM encrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(options.getRawPayload().getBytes(StandardCharsets.UTF_8));

            // Output nonce||ciphertext
            byte[] output = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, output, 0, nonce.length);
            System.arraycopy(ciphertext, 0, output, nonce.length, ciphertext.length);

            String base64Ciphertext = java.util.Base64.getEncoder().encodeToString(output);
            options.setSecuredPayload(base64Ciphertext);
            return base64Ciphertext;
        } catch (Exception ex) {
            throw new EncryptionException("Failed to encrypt data by ECIES SECP384R1 TUBITAK", ex);
        }
    }

    @Override
    public String decrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        try {
            if (options.getSecuredPayload() == null || options.getSecuredPayload().isEmpty()) {
                return options.getSecuredPayload();
            }

            if (options.getEncryptionParams() == null || options.getEncryptionParams().getEcies() == null) {
                throw new EncryptionException("Failed to decrypt data by ECIES SECP384R1 TUBITAK, encryption params nil");
            }

            PrivateKey recipientPrivateKey = CryptoUtils.pemToPrivateKey(options.getReceiverKeyInfo().getPrivateKey());
            PublicKey senderPublicKey = CryptoUtils.pemToPublicKey(options.getInitiatorKeyInfo().getPublicKey());

            // Deserialize ephemeral public key
            ECPublicKey ephemeralPub = getShardPublicKey(options.getEncryptionParams().getEcies().getEphemeralPublicKey());

            // Decode base64 ciphertext
            byte[] data = java.util.Base64.getDecoder().decode(options.getSecuredPayload());
            if (data.length < GCM_NONCE_LENGTH) {
                throw new IllegalArgumentException("Ciphertext too short");
            }
            byte[] nonce = Arrays.copyOfRange(data, 0, GCM_NONCE_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(data, GCM_NONCE_LENGTH, data.length);

            // Compute shared secrets
            byte[] sharedSecret1 = ecdhSharedSecret(recipientPrivateKey, senderPublicKey);
            byte[] sharedSecret2 = ecdhSharedSecret(recipientPrivateKey, ephemeralPub);

            // Derive AES key
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(sharedSecret1);
            sha256.update(sharedSecret2);
            byte[] aesKey = sha256.digest();

            // AES-GCM decrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            String rawPayload = new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
            options.setRawPayload(rawPayload);
            return rawPayload;
        } catch (Exception ex) {
            throw new EncryptionException("Failed to decrypt data by ECIES SECP384R1 TUBITAK", ex);
        }
    }

    // Get ECParameterSpec for secp384r1
    private ECParameterSpec getECParameterSpec() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp384r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (Exception ex) {
            throw new EncryptionException("get EC Parameter Spec fail", ex);
        }
    }

    private byte[] ecdhSharedSecret(PrivateKey privateKey, PublicKey pubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(pubKey, true);
        byte[] fullSecret = ka.generateSecret();

        // fullSecret is the X coordinate per Java spec for ECDH
        // Pad to curve size bytes if needed
        ECParameterSpec ecSpec = getECParameterSpec();
        int keySizeBytes = (ecSpec.getCurve().getField().getFieldSize() + 7) >> 3;

        if (fullSecret.length == keySizeBytes) {
            return fullSecret;
        } else if (fullSecret.length < keySizeBytes) {
            byte[] padded = new byte[keySizeBytes];
            System.arraycopy(fullSecret, 0, padded, keySizeBytes - fullSecret.length, fullSecret.length);
            return padded;
        } else {
            throw new EncryptionException("ECDH secret length is longer than expected");
        }
    }

    public static ECPublicKey getShardPublicKey(String base64EphemeralPublicKey) throws Exception {
        byte[] decodedKey = java.util.Base64.getDecoder().decode(base64EphemeralPublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return (ECPublicKey) publicKey;
    }
}
