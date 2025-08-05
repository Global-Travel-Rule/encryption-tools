/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/19 19:04
 */

package com.globaltravelrule.encryption.impl.libsodium;

import com.globaltravelrule.encryption.core.api.EncryptAndDecryptExecutor;
import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;
import com.globaltravelrule.sodium.LazySodium;
import com.globaltravelrule.sodium.LazySodiumJava;
import com.globaltravelrule.sodium.SodiumJava;
import com.globaltravelrule.sodium.exceptions.SodiumException;
import com.globaltravelrule.sodium.interfaces.AEAD;
import com.globaltravelrule.sodium.interfaces.Box;
import com.globaltravelrule.sodium.interfaces.MessageEncoder;
import com.globaltravelrule.sodium.interfaces.Sign;
import com.globaltravelrule.sodium.utils.Key;
import com.globaltravelrule.sodium.utils.KeyPair;
import com.globaltravelrule.sodium.utils.LibraryLoader;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

/**
 * executes encryption and decryption using Ed25519 and Curve25519 algorithms.
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class Ed25519Curve25519Executor implements EncryptAndDecryptExecutor {

    private static final LazySodium sodium;

    static {
        sodium = new LazySodiumJava(new SodiumJava(LibraryLoader.Mode.PREFER_BUNDLED), new MessageEncoder() {
            @Override
            public String encode(byte[] cipher) {
                if (cipher == null || cipher.length == 0) {
                    return "";
                }
                return Base64.toBase64String(cipher);
            }

            @Override
            public byte[] decode(String cipherText) {
                if (cipherText == null || cipherText.isEmpty()) {
                    return new byte[0];
                }
                return Base64.decode(cipherText.getBytes(StandardCharsets.UTF_8));
            }
        });
        sodium.sodiumInit();
    }

    @Override
    public EncryptionAlgorithm getCryptionAlgorithm() {
        return EncryptionAlgorithm.ED25519_CURVE25519;
    }

    @Override
    public EncryptionKeyPair generateKeyPair(GenerateKeyPairOptions options) throws EncryptionException {
        try {
            Key seed = sodium.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
            KeyPair keyPair = sodium.cryptoSignSeedKeypair(seed.getAsBytes());
            return new EncryptionKeyPair(
                    Base64.toBase64String(keyPair.getPublicKey().getAsBytes()),
                    Base64.toBase64String(keyPair.getSecretKey().getAsBytes()));
        } catch (Exception ex) {
            throw new EncryptionException("Failed to generate ED25519 key pair", ex);
        }
    }

    @Override
    public String encrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        try {
            if (options.getRawPayload() == null || options.getRawPayload().isEmpty()) {
                return options.getRawPayload();
            }
            byte[] secretKey = generateSecretKey(options.getReceiverKeyInfo().getPublicKey(), options.getInitiatorKeyInfo().getPrivateKey());

            byte[] plainData = options.getRawPayload().getBytes(StandardCharsets.UTF_8);
            byte[] nonce = sodium.randomBytesBuf(Box.NONCEBYTES);
            byte[] encryptedData = new byte[plainData.length + Box.MACBYTES];
            if (!sodium.cryptoBoxEasyAfterNm(encryptedData, plainData, plainData.length, nonce, secretKey)) {
                throw new SodiumException("Could not encrypt data");
            }

            //Splicing Nonce
            byte[] encryptedFullData = new byte[nonce.length + encryptedData.length];
            System.arraycopy(nonce, 0, encryptedFullData, 0, nonce.length);
            System.arraycopy(encryptedData, 0, encryptedFullData, nonce.length, encryptedData.length);

            String securedPayload = new String(Base64.encode(encryptedFullData));
            options.setSecuredPayload(securedPayload);
            return securedPayload;
        } catch (Exception ex) {
            throw new EncryptionException("Failed to encrypt data by Ed25519Curve25519", ex);
        }
    }

    @Override
    public String decrypt(EncryptionAndDecryptionOptions options) throws EncryptionException {
        try {
            if (options.getSecuredPayload() == null || options.getSecuredPayload().isEmpty()) {
                return options.getSecuredPayload();
            }
            byte[] secretKeyBytes = Arrays.copyOfRange(
                    Base64.decode(options.getReceiverKeyInfo().getPrivateKey()), 0, Sign.CURVE25519_SECRETKEYBYTES);
            String processPrivateKey = Base64.toBase64String(secretKeyBytes);
            byte[] secretKey = generateSecretKey(options.getInitiatorKeyInfo().getPublicKey(), processPrivateKey);

            // Compatible with separating nonce and ciphertext
            byte[] fullCiphertextData = Base64.decode(options.getSecuredPayload());
            byte[] nonce = java.util.Arrays.copyOfRange(fullCiphertextData, 0, Box.NONCEBYTES);
            byte[] ciphertextData = Arrays.copyOfRange(fullCiphertextData, Box.NONCEBYTES, fullCiphertextData.length);
            byte[] plaintextData = new byte[ciphertextData.length - Box.MACBYTES];

            if (!sodium.cryptoBoxOpenEasyAfterNm(plaintextData, ciphertextData, ciphertextData.length, nonce, secretKey)) {
                throw new SodiumException("could not decrypt data");
            }

            String rawPayload = new String(plaintextData, StandardCharsets.UTF_8);
            options.setRawPayload(rawPayload);
            return rawPayload;
        } catch (Exception ex) {
            throw new EncryptionException("Failed to decrypt data by Ed25519Curve25519", ex);
        }
    }

    private byte[] generateSecretKey(String base64RemotePublicKey, String base64HostedPrivateKey) {
        byte[] sharedKey = new byte[Box.BEFORENMBYTES];
        byte[] curPublicKey = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        byte[] curPrivateKey = new byte[Sign.CURVE25519_SECRETKEYBYTES];
        sodium.convertPublicKeyEd25519ToCurve25519(curPublicKey, Base64.decode(base64RemotePublicKey.getBytes(StandardCharsets.UTF_8)));
        sodium.convertSecretKeyEd25519ToCurve25519(curPrivateKey, Base64.decode(base64HostedPrivateKey.getBytes(StandardCharsets.UTF_8)));
        sodium.cryptoBoxBeforeNm(sharedKey, curPublicKey, curPrivateKey);
        return sharedKey;
    }
}
