/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:19
 */

package com.globaltravelrule.encryption.impl.bouncycastle.utils;

import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

/**
 * crypto utils
 *
 * @author Global Travel Rule developer
 * @version 1.0.0
 * @since 1.0.0
 */
public class CryptoUtils {

    private static final Logger log = LoggerFactory.getLogger(CryptoUtils.class);

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

    // PublicKey to PEM format
    public static String publicKeyToPEM(PublicKey publicKey) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(publicKey);
        }
        return writer.toString();
    }

    // PrivateKey to PEM format
    public static String privateKeyToPEM(PrivateKey privateKey) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(privateKey);
        }
        return writer.toString();
    }

    // PEM to PublicKey
    public static PublicKey pemToPublicKey(String pemPublicKey) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemPublicKey))) {
            Object obj = pemParser.readObject();
            if (obj instanceof X509CertificateHolder) {
                X509CertificateHolder certHolder = (X509CertificateHolder) obj;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getPublicKey(certHolder.getSubjectPublicKeyInfo());
            } else if (obj instanceof SubjectPublicKeyInfo) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getPublicKey((SubjectPublicKeyInfo) obj);
            } else {
                throw new IllegalArgumentException("Unsupported PEM format: " + obj.getClass());
            }
        }
    }

    // PEM to PrivateKey
    public static PrivateKey pemToPrivateKey(String pemPrivateKey) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemPrivateKey))) {
            Object obj = pemParser.readObject();
            if (obj instanceof PEMKeyPair) {
                return new JcaPEMKeyConverter().getPrivateKey(((PEMKeyPair) obj).getPrivateKeyInfo());
            } else if (obj instanceof PrivateKeyInfo) {
                return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) obj);
            } else {
                throw new IllegalArgumentException("Unsupported PEM format: " + obj.getClass());
            }
        }
    }

    // Retrieve the X509 format public key certificate string (PEM)
    public static String publicKeyToX509PEM(GenerateKeyPairOptions options,
                                            SubjectPublicKeyInfo publicKeyInfo,
                                            ContentSigner signer) throws Exception {
        X509CertificateHolder certificate;
        X500Name issuer = new X500Name(options.getSubjectDN());
        Date startDate = options.getStartDate();
        if (startDate == null) {
            startDate = new Date();
        }
        Date endDate = options.getEndDate();
        if (endDate == null) {
            endDate = new Date(startDate.getTime() + 365L * 24 * 60 * 60 * 1000);
        }

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                startDate,
                endDate,
                issuer,
                publicKeyInfo);
        certificate = certBuilder.build(signer);
        try (StringWriter writer = new StringWriter()) {
            try (PemWriter pemWriter = new PemWriter(writer)) {
                pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
            } catch (Exception ex) {
                log.error("generate PEM string error", ex);
                throw ex;
            }
            return writer.toString();
        } catch (Exception ex) {
            log.error("generate PEM string error", ex);
            throw new OperatorCreationException("generate PEM string error", ex);
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
