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
import com.globaltravelrule.encryption.impl.bouncycastle.utils.CryptoUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * ecies p256 sygna executor
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class EciesSecp256k1SygnaExecutor extends EciesExecutor {

    private static final int IV_LENGTH = 16;
    private static final int MAC_LENGTH = 20; // HMAC-SHA1 output length in bytes
    private static final int EPHEMERAL_PUBKEY_LENGTH = 65; // uncompressed EC point (0x04 + 32-byte X + 32-byte Y)

    @Override
    public EncryptionAlgorithm getCryptionAlgorithm() {
        return EncryptionAlgorithm.ECIES_SECP256K1_SYGNA;
    }

    @Override
    public EncryptionKeyPair generateKeyPair(GenerateKeyPairOptions options) throws EncryptionException {
        return doGenerateKeyPair(options, CurveType.SECP256R1);
    }

    @Override
    public String encrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        try {
            // 1. Generate ephemeral EC key pair on secp256k1
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new ECGenParameterSpec(CurveType.SECP256R1.getCurveName()));
            KeyPair ephemeralKP = kpg.generateKeyPair();
            PrivateKey ephemeralPri = ephemeralKP.getPrivate();
            PublicKey ephemeralPub = ephemeralKP.getPublic();

            // 2. Compute shared secret: ephemeralPriv * recipientPublicKey
            PublicKey recipientPublicKey = CryptoUtils.pemToPublicKey(options.getReceiverKeyInfo().getPublicKey());
            byte[] sharedSecret = ecdhSharedSecret(ephemeralPri, recipientPublicKey);

            // 3. Hash shared secret with SHA-512
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashedSecret = sha512.digest(sharedSecret);

            // 4. Split hashedSecret into encryptionKey (first 32 bytes) and macKey (last 32 bytes)
            byte[] encryptionKey = Arrays.copyOfRange(hashedSecret, 0, 32);
            byte[] macKey = Arrays.copyOfRange(hashedSecret, 32, 64);

            // 5. AES-256-CBC encrypt with IV = 16 zero bytes
            byte[] iv = new byte[IV_LENGTH]; // zero-filled by default
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec aesKeySpec = new SecretKeySpec(encryptionKey, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(options.getRawPayload().getBytes(StandardCharsets.UTF_8));

            // 6. Serialize ephemeral public key in uncompressed form (65 bytes)
            byte[] ephemeralPubBytes = serializePublicKey((ECPublicKey) ephemeralPub);

            // 7. Compute HMAC-SHA1 over (iv || ephemeralPubKey || ciphertext)
            ByteBuffer dataToMacBuffer = ByteBuffer.allocate(iv.length + ephemeralPubBytes.length + ciphertext.length);
            dataToMacBuffer.put(iv);
            dataToMacBuffer.put(ephemeralPubBytes);
            dataToMacBuffer.put(ciphertext);
            byte[] dataToMac = dataToMacBuffer.array();

            Mac hmacSha1 = Mac.getInstance("HmacSHA1", "BC");
            SecretKeySpec macKeySpec = new SecretKeySpec(macKey, "HmacSHA1");
            hmacSha1.init(macKeySpec);
            byte[] mac = hmacSha1.doFinal(dataToMac);


            // 8. Concatenate ephemeralPubKey || mac || ciphertext
            ByteBuffer outputBuffer = ByteBuffer.allocate(ephemeralPubBytes.length + mac.length + ciphertext.length);
            outputBuffer.put(ephemeralPubBytes);
            outputBuffer.put(mac);
            outputBuffer.put(ciphertext);
            byte[] encData = outputBuffer.array();

            // 9. Return hex string
            return bytesToHex(encData);
        } catch (Exception ex) {
            throw new EncryptionException("Failed to encrypt data by ECIES SECP256R1 SYGNA", ex);
        }
    }

    @Override
    public String decrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        try {
            if (options.getSecuredPayload() == null || options.getSecuredPayload().isEmpty()) {
                return options.getSecuredPayload();
            }

            byte[] encryptedMsg = hexToBytes(options.getSecuredPayload());
            if (encryptedMsg.length < EPHEMERAL_PUBKEY_LENGTH + MAC_LENGTH) {
                throw new IllegalArgumentException("Encrypted message too short");
            }
            // Extract ephemeralPubKey, mac, ciphertext
            byte[] ephemeralPubKey = Arrays.copyOfRange(encryptedMsg, 0, EPHEMERAL_PUBKEY_LENGTH);
            byte[] mac = Arrays.copyOfRange(encryptedMsg, EPHEMERAL_PUBKEY_LENGTH, EPHEMERAL_PUBKEY_LENGTH + MAC_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(encryptedMsg, EPHEMERAL_PUBKEY_LENGTH + MAC_LENGTH, encryptedMsg.length);

            // Compute shared secret: recipientPrivateKey * ephemeralPubKey
            PublicKey ephemeralPub = decodePublicKey(ephemeralPubKey);
            PrivateKey recipientPrivateKey = CryptoUtils.pemToPrivateKey(options.getReceiverKeyInfo().getPrivateKey());
            byte[] sharedSecret = ecdhSharedSecret(recipientPrivateKey, ephemeralPub);

            // Hash shared secret with SHA-512
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashedSecret = sha512.digest(sharedSecret);

            // Split keys
            byte[] encryptionKey = Arrays.copyOfRange(hashedSecret, 0, 32);
            byte[] macKey = Arrays.copyOfRange(hashedSecret, 32, 64);

            // IV = 16 zero bytes
            byte[] iv = new byte[IV_LENGTH];

            // Compute MAC over (iv || ephemeralPubKey || ciphertext)
            ByteBuffer dataToMacBuffer = ByteBuffer.allocate(iv.length + ephemeralPubKey.length + ciphertext.length);
            dataToMacBuffer.put(iv);
            dataToMacBuffer.put(ephemeralPubKey);
            dataToMacBuffer.put(ciphertext);
            byte[] dataToMac = dataToMacBuffer.array();

            Mac hmacSha1 = Mac.getInstance("HmacSHA1", "BC");
            SecretKeySpec macKeySpec = new SecretKeySpec(macKey, "HmacSHA1");
            hmacSha1.init(macKeySpec);
            byte[] realMac = hmacSha1.doFinal(dataToMac);

            // Verify MAC constant time
            if (!constantTimeEquals(mac, realMac)) {
                throw new IllegalArgumentException("MAC verification failed");
            }

            // Decrypt ciphertext
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec aesKeySpec = new SecretKeySpec(encryptionKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivSpec);
            byte[] plaintext = cipher.doFinal(ciphertext);

            return new String(plaintext);
        } catch (Exception ex) {
            throw new EncryptionException("Failed to decrypt data by ECIES SECP256R1 SYGNA", ex);
        }
    }

    // ECDH shared secret computation
    private byte[] ecdhSharedSecret(PrivateKey privateKey, PublicKey pubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(privateKey);
        ka.doPhase(pubKey, true);
        return ka.generateSecret();
    }

    // Serialize EC public key in uncompressed form (0x04 || X || Y)
    private byte[] serializePublicKey(ECPublicKey pubKey) {
        ECPoint w = pubKey.getW();
        byte[] x = toFixedLength(w.getAffineX().toByteArray(), 32);
        byte[] y = toFixedLength(w.getAffineY().toByteArray(), 32);

        byte[] serialized = new byte[1 + x.length + y.length];
        serialized[0] = 0x04; // uncompressed point indicator
        System.arraycopy(x, 0, serialized, 1, x.length);
        System.arraycopy(y, 0, serialized, 1 + x.length, y.length);
        return serialized;
    }

    // Convert byte array to fixed length (pad or trim)
    private static byte[] toFixedLength(byte[] arr, int length) {
        if (arr.length == length) {
            return arr;
        } else if (arr.length > length) {
            // Trim leading zeros if longer
            return Arrays.copyOfRange(arr, arr.length - length, arr.length);
        } else {
            // Pad with leading zeros if shorter
            byte[] result = new byte[length];
            System.arraycopy(arr, 0, result, length - arr.length, arr.length);
            return result;
        }
    }

    // bytes to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    // hex string to bytes
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) throw new IllegalArgumentException("Invalid hex string length");
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Decode uncompressed EC public key bytes (65 bytes) to PublicKey instance.
     *
     * @param uncompressedPubKey 65-byte uncompressed EC public key (0x04 + X + Y)
     * @return PublicKey instance
     * @throws Exception on invalid format or decoding error
     */
    public PublicKey decodePublicKey(byte[] uncompressedPubKey) throws Exception {
        if (uncompressedPubKey.length != EPHEMERAL_PUBKEY_LENGTH || uncompressedPubKey[0] != 0x04) {
            throw new IllegalArgumentException("Invalid uncompressed EC public key format");
        }
        byte[] x = Arrays.copyOfRange(uncompressedPubKey, 1, 33);
        byte[] y = Arrays.copyOfRange(uncompressedPubKey, 33, 65);

        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
        parameters.init(new ECGenParameterSpec(CurveType.SECP256R1.getCurveName()));
        ECParameterSpec params = parameters.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec pubSpec = new ECPublicKeySpec(
                new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), params);
        return kf.generatePublic(pubSpec);
    }

    // constant time byte array comparison
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
