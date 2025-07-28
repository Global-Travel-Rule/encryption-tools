/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle;

import com.globaltravelrule.encryption.core.api.EncryptAndDecryptExecutor;
import com.globaltravelrule.encryption.core.enums.EncryptionKeyFormat;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;
import com.globaltravelrule.encryption.impl.bouncycastle.enums.CurveType;
import com.globaltravelrule.encryption.impl.bouncycastle.utils.CryptoUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

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

    protected EncryptionKeyPair doGenerateKeyPair(GenerateKeyPairOptions options, CurveType curveType) throws EncryptionException {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveType.getCurveName());
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, "BC");
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            if (EncryptionKeyFormat.X509.getFormat().equals(options.getKeyFormat())) {
                ContentSigner signer = new JcaContentSignerBuilder(getSignatureAlgorithmForCurve(curveType))
                        .build(keyPair.getPrivate());
                return new EncryptionKeyPair(
                        CryptoUtils.publicKeyToX509PEM(options,
                                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()),
                                signer),
                        CryptoUtils.privateKeyToPEM(keyPair.getPrivate()));
            } else {
                return new EncryptionKeyPair(
                        CryptoUtils.publicKeyToPEM(keyPair.getPublic()),
                        CryptoUtils.privateKeyToPEM(keyPair.getPrivate())
                );
            }
        } catch (Exception ex) {
            throw new EncryptionException("Failed to generate key pair for ECIES encryption", ex);
        }
    }

    /**
     * Encrypted data
     *
     * @param options   encryption info
     * @param curveType curve type
     * @return encrypted data (base64)
     */
    protected String encrypt(EncryptionAndDecryptionOptions options, CurveType curveType) {
        try {
            if (options.getRawPayload() == null || options.getRawPayload().isEmpty()) {
                return options.getRawPayload();
            }

            // 1. Ensure to use non-compressed format
            ECPublicKey receiverPubKey = (ECPublicKey) CryptoUtils.pemToPublicKey(options.getReceiverKeyInfo().getPublicKey());

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
            byte[] ciphertext = cipher.doFinal(options.getRawPayload().getBytes(StandardCharsets.UTF_8));
            String securedPayload = Base64.toBase64String(ByteBuffer.allocate(16 + ciphertext.length)
                    .put(nonce)
                    .put(ciphertext)
                    .array());
            options.setSecuredPayload(securedPayload);
            return securedPayload;
        } catch (Exception ex) {
            throw new EncryptionException("Failed to encrypt data by ECIES", ex);
        }
    }

    /**
     * Decrypt data
     *
     * @param options   decryption info
     * @param curveType curve type
     * @return decrypted plaintext
     */
    protected String decrypt(EncryptionAndDecryptionOptions options, CurveType curveType) {
        try {
            if (options.getSecuredPayload() == null || options.getSecuredPayload().isEmpty()) {
                return options.getSecuredPayload();
            }

            byte[] ciphertextData = Base64.decode(options.getSecuredPayload());

            Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC", "BC");
            IESParameterSpec params = new IESParameterSpec(
                    null, null, getMacKeySize(curveType), KEY_SIZE,
                    extractNonceFromCiphertext(ciphertextData),
                    false
            );
            cipher.init(Cipher.DECRYPT_MODE, CryptoUtils.pemToPrivateKey(options.getReceiverKeyInfo().getPrivateKey()), params);
            String rawPayload = new String(cipher.doFinal(removeNonceFromCiphertext(ciphertextData)));
            options.setRawPayload(rawPayload);
            return rawPayload;
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

    private String getSignatureAlgorithmForCurve(CurveType curveType) {
        switch (curveType) {
            case SECP384R1:
                return "SHA384withECDSA";
            case SECP521R1:
            case SECT571K1:
                return "SHA512withECDSA";
            default:
                return "SHA256withECDSA";
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
