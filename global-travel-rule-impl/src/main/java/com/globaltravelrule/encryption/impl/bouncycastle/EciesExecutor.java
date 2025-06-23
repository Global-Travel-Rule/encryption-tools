/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.api.EncryptAndDecryptExecutor;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.impl.bouncycastle.enums.CurveType;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ecies encryption and decryption base class
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public abstract class EciesExecutor implements EncryptAndDecryptExecutor {

    private static final String KEY_ALGORITHM = "EC";

    private static final Integer KEY_SIZE = 256;

    private static final Integer NONCE_SIZE = 16;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected EncryptionKeyPair doGenerateKeyPair(CurveType curveType) throws EncryptionException {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveType.getCurveName());
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, "BC");
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return new EncryptionKeyPair(
                    // X.509格式
                    Base64.toBase64String(keyPair.getPublic().getEncoded()),
                    // PKCS#8格式
                    Base64.toBase64String(keyPair.getPrivate().getEncoded())
            );
        } catch (Exception ex) {
            throw new EncryptionException("Failed to generate key pair for ECIES encryption", ex);
        }
    }

    /**
     * Encrypted data
     *
     * @param base64PublicKey Receiver's public key(base64)
     * @param plaintext       Data to be encrypted
     * @param curveType       curve type
     * @return encrypted data (base64)
     */
    protected String encrypt(String base64PublicKey, String plaintext, CurveType curveType) {
        try {
            if (plaintext == null || plaintext.isEmpty()) {
                return plaintext;
            }

            // 1. Ensure to use non-compressed format
            ECPublicKey receiverPubKey = (ECPublicKey) base64ToPublicKey(base64PublicKey);

            byte[] uncompressedPubKey = toUncompressedPoint(receiverPubKey);
            ECPublicKey normalizedKey = parseECPublicKey(uncompressedPubKey, curveType.getCurveName());

            // 2. Initialize the encryptor
            Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC", "BC");
            byte[] nonce = generateNonce();

            IESParameterSpec params = new IESParameterSpec(
                    null, null, getMacKeySize(curveType), KEY_SIZE, nonce, false // 必须禁用压缩
            );

            // 3. Encrypt and combine data packets
            cipher.init(Cipher.ENCRYPT_MODE, normalizedKey, params);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.toBase64String(ByteBuffer.allocate(16 + ciphertext.length)
                    .put(nonce)
                    .put(ciphertext)
                    .array());
        } catch (Exception ex) {
            throw new EncryptionException("Failed to encrypt data by ECIES", ex);
        }
    }

    /**
     * Decrypt data
     *
     * @param base64PrivateKey Recipient's private key(base64)
     * @param base64Ciphertext Decrypt data(base64)
     * @param curveType        curve type
     * @return decrypted plaintext
     */
    protected String decrypt(String base64PrivateKey, String base64Ciphertext, CurveType curveType) {
        try {
            if (base64Ciphertext == null || base64Ciphertext.isEmpty()) {
                return base64Ciphertext;
            }

            byte[] ciphertextData = Base64.decode(base64Ciphertext);

            Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC", "BC");
            IESParameterSpec params = new IESParameterSpec(
                    null, null, getMacKeySize(curveType), KEY_SIZE,
                    extractNonceFromCiphertext(ciphertextData),
                    false
            );
            cipher.init(Cipher.DECRYPT_MODE, base64ToPrivateKey(base64PrivateKey), params);
            return new String(cipher.doFinal(removeNonceFromCiphertext(ciphertextData)));
        } catch (Exception ex) {
            throw new EncryptionException("Failed to decrypt data by ECIES", ex);
        }
    }

    /**
     * Obtain the MAC key length corresponding to each curve
     */
    private int getMacKeySize(CurveType curveType) {
        switch (curveType) {
            case SECP256R1:
            case SECT256K1:
                return 256;
            case SECP384R1:
                return 384;
            case SECP521R1:
            case SECT571K1:
                return 512;
            default:
                throw new EncryptionException("Unsupported curve type:" + curveType.getCurveName());
        }
    }

    /**
     * Generate random nonce
     */
    private byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // Base64 to public key conversion
    private PublicKey base64ToPublicKey(String base64Key) throws Exception {
        byte[] decoded = Base64.decode(base64Key);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new X509EncodedKeySpec(decoded));
    }

    // Convert the public key to a standard uncompressed format (65 bytes, starting with 0x04)
    private byte[] toUncompressedPoint(ECPublicKey pubKey) {
        return pubKey.getQ().getEncoded(false); // false表示非压缩
    }

    // Reconstruct EC public key from bytes
    private ECPublicKey parseECPublicKey(byte[] uncompressedPoint, String curveName)
            throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
        ECPoint point = ecSpec.getCurve().decodePoint(uncompressedPoint);
        return (ECPublicKey) KeyFactory.getInstance("EC", "BC")
                .generatePublic(new ECPublicKeySpec(point, ecSpec));
    }

    // Base64 to private key conversion
    private PrivateKey base64ToPrivateKey(String base64Key) throws Exception {
        byte[] decoded = Base64.decode(base64Key);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }


    // Extract nonce from composite data
    private byte[] extractNonceFromCiphertext(byte[] combined) {
        byte[] nonce = new byte[16];
        System.arraycopy(combined, 0, nonce, 0, 16);
        return nonce;
    }

    // Obtain actual ciphertext from combined data
    private byte[] removeNonceFromCiphertext(byte[] combined) {
        byte[] ciphertext = new byte[combined.length - 16];
        System.arraycopy(combined, 16, ciphertext, 0, ciphertext.length);
        return ciphertext;
    }
}
