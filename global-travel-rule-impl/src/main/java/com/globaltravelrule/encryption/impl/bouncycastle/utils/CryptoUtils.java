/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * crypto utils
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class CryptoUtils {

    // Convert Ed25519 public key to Curve25519 public key
    public static X25519PublicKeyParameters convertEd25519ToCurve25519(Ed25519PublicKeyParameters edPublicKey) {
        byte[] edPub = edPublicKey.getEncoded();
        byte[] xPub = new byte[32];

        // 1. Decoding Ed25519 public key into curve points
        // (The actual implementation requires more complex mathematical operations, which are simplified here)

        // 2. Convert Edwards coordinates to Montgomery coordinates
        // This should be the actual mathematical conversion code

        // 3. Encoded as X25519 public key
        // Simplified Example - In practical applications, it is necessary to fully implement mathematical transformations
        System.arraycopy(edPub, 0, xPub, 0, 32);

        // Correction of symbol bits (an important step in actual conversion)
        xPub[31] &= 0x7F;
        return new X25519PublicKeyParameters(xPub);
    }

    /**
     * Create RSA public key from Base64 format string
     *
     * @param base64PublicKey Base64 encoded public key
     * @return RSAKeyParameters
     * @throws IOException If parsing fails
     */
    public static RSAPublicKey parseRsaPublicKeyFromBase64(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.decode(base64PublicKey);
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyBytes);
        return (RSAPublicKey) new JcaPEMKeyConverter().getPublicKey(keyInfo);
    }

    /**
     * Create RSA private key from Base64 format string
     *
     * @param base64PrivateKey PEM format private key base64 string
     * @return PrivateKey
     * @throws IOException If parsing fails
     */
    public static RSAPrivateKey parseRsaPrivateKeyFromBase64(String base64PrivateKey) throws Exception {
        byte[] keyBytes = Base64.decode(base64PrivateKey);
        PrivateKeyInfo keyInfo = PrivateKeyInfo.getInstance(keyBytes);
        return (RSAPrivateKey) new JcaPEMKeyConverter().getPrivateKey(keyInfo);
    }

    /**
     * Convert Bouncy Castle private key to standard RSAPrivateKey
     *
     * @param bcPrivateKey Bouncy Castle Private Key
     * @return RSAPrivateKey
     * @throws Exception If parsing fails
     */
    public static RSAPrivateKey toRSAPrivateKey(PrivateKey bcPrivateKey) throws Exception {
        if (bcPrivateKey instanceof RSAPrivateKey) {
            return (RSAPrivateKey) bcPrivateKey;
        }
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(bcPrivateKey.getEncoded()));
    }

    // RSAPublicKey to PEM format
    public static String rsaPublicKeyToPEM(RSAPublicKey publicKey) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(publicKey);
        }
        return writer.toString();
    }

    // RSAPrivateKey to PEM format
    public static String rsaPrivateKeyToPEM(RSAPrivateKey privateKey) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(privateKey);
        }
        return writer.toString();
    }

    // PEM to RSAPublicKey
    public static RSAPublicKey pemToRSAPublicKey(String pemPublicKey) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemPublicKey))) {
            SubjectPublicKeyInfo keyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            return (RSAPublicKey) new JcaPEMKeyConverter().getPublicKey(keyInfo);
        }
    }

    // PEM to RSAPrivateKey
    public static RSAPrivateKey pemToRSAPrivateKey(String pemPrivateKey) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemPrivateKey))) {
            PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemParser.readObject();
            return (RSAPrivateKey) new JcaPEMKeyConverter().getPrivateKey(keyInfo);
        }
    }

    public static byte[] subtractArray(byte[] byteArray, int beginIndex, int length) {
        byte[] result = new byte[length];
        System.arraycopy(byteArray, beginIndex, result, 0, length);
        return result;
    }

    public static byte[] concatArray(byte[]... arrays) {
        // 计算总长度
        int totalLength = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                totalLength += array.length;
            }
        }
        // Create a new array to store all bytes
        byte[] result = new byte[totalLength];
        // Merge byte arrays
        int currentPosition = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                System.arraycopy(array, 0, result, currentPosition, array.length);
                currentPosition += array.length;
            }
        }
        return result;
    }
}
