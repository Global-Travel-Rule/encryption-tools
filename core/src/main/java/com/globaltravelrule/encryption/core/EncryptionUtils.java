/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/6/9 12:20
 */

package com.globaltravelrule.encryption.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import com.globaltravelrule.encryption.core.api.EncryptAndDecryptExecutor;
import com.globaltravelrule.encryption.core.enums.EncryptionAlgorithm;
import com.globaltravelrule.encryption.core.enums.EncryptionFormat;
import com.globaltravelrule.encryption.core.exceptions.EncryptionException;
import com.globaltravelrule.encryption.core.options.EncryptionAndDecryptionOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;
import com.globaltravelrule.encryption.core.options.GenerateKeyPairOptions;
import com.globaltravelrule.encryption.core.options.PiiSecuredInfo;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Utility class for encryption and decryption operations.
 */
public class EncryptionUtils {

    public static final String ENCRYPTION_ACTION = "encrypt";
    public static final String DECRYPTION_ACTION = "decrypt";

    private static volatile EncryptionUtils instance;

    private EncryptionUtils() {

    }

    private Map<EncryptionAlgorithm, EncryptAndDecryptExecutor> ENCRYPTION_ALGORITHMS_HOLDER;

    private ObjectMapper objectMapper;

    private static EncryptionUtils getInstance() {
        if (instance == null) {
            synchronized (EncryptionUtils.class) {
                if (instance == null) {
                    instance = new EncryptionUtils();
                    instance.initialize();
                }
            }
        }
        return instance;
    }

    private void initialize() {
        objectMapper = new ObjectMapper();
        ENCRYPTION_ALGORITHMS_HOLDER = new HashMap<>();
        ServiceLoader<EncryptAndDecryptExecutor> loader = ServiceLoader.load(EncryptAndDecryptExecutor.class);
        loader.forEach(executor -> {
            if (ENCRYPTION_ALGORITHMS_HOLDER.containsKey(executor.getCryptionAlgorithm())) {
                throw new EncryptionException("Duplicate encryption algorithm: " + executor.getCryptionAlgorithm() + ", please check your encryption implementation dependencies config.");
            }
            ENCRYPTION_ALGORITHMS_HOLDER.put(executor.getCryptionAlgorithm(), executor);
        });
    }

    private EncryptAndDecryptExecutor getCryptionExecutor(String algorithmType) {
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.parse(algorithmType);
        if (algorithm == null) {
            throw new EncryptionException("Unsupported encryption algorithm: " + algorithmType);
        }
        if (!ENCRYPTION_ALGORITHMS_HOLDER.containsKey(algorithm)) {
            throw new EncryptionException("Unsupported encryption algorithm: " + algorithm + ", please check your encryption implementation dependencies config.");
        }
        return ENCRYPTION_ALGORITHMS_HOLDER.get(algorithm);
    }

    /**
     * Generate a key pair for the specified algorithm.
     *
     * @param options generating options
     * @return the key pair
     * @throws EncryptionException if the algorithm is not supported or other encryption-related errors occur
     */
    private EncryptionKeyPair doGenerateKeyPair(GenerateKeyPairOptions options) {
        if (options.getAlgorithmType() == null) {
            throw new EncryptionException("encryption algorithm invalid");
        }
        EncryptAndDecryptExecutor executor = getCryptionExecutor(options.getAlgorithmType());
        return executor.generateKeyPair(options);
    }

    /**
     * Encrypt the plain text using the specified algorithm and options.
     * Decrypt the encrypted text using the specified algorithm and options.
     *
     * @param options the encryption or decryption info
     */
    private void doEncryptAndDecrypt(EncryptionAndDecryptionOptions options, String action) {
        EncryptAndDecryptExecutor executor = getCryptionExecutor(options.getAlgorithmType());
        String payload;
        EncryptionFormat format = EncryptionFormat.parse(options.getEncryptionFormatType());
        switch (format) {
            case FULL_JSON_OBJECT_ENCRYPT:
                payload = encryptAndDecryptString(executor, options, action);
                break;
            case JSON_FIELD_ENCRYPT:
            case JSON_FIELD_HASHED:
                payload = encryptAndDecryptJsonData(executor, options, action);
                break;
            default:
                throw new EncryptionException("Unsupported PII Secret Format Type: " + options.getEncryptionFormatType());
        }
        processPiiSecuredInfo(payload, options, action);
    }

    private void processPiiSecuredInfo(String payload, EncryptionAndDecryptionOptions options, String action) {
        if (ENCRYPTION_ACTION.equals(action)) {
            options.setSecuredPayload(payload);

            //clear sensitive information
            options.setRawPayload(null);
            if (options.getInitiatorKeyInfo() != null) {
                options.getInitiatorKeyInfo().setPrivateKey(null);
            }
        }
        if (DECRYPTION_ACTION.equals(action)) {
            options.setRawPayload(payload);

            //clear sensitive information
            options.setSecuredPayload(null);
            if (options.getReceiverKeyInfo() != null) {
                options.getReceiverKeyInfo().setPrivateKey(null);
            }
        }
    }

    /**
     * Encrypt all strings and basic type fields in JSON strings
     *
     * @param executor CryptionExecutor instance for encryption
     * @param options  info for encryption and decryption
     * @param action   "encrypt" or "decrypt"
     * @return Encrypted JSON string
     * @throws EncryptionException If JSON is illegal or encryption error occurs
     */
    private String encryptAndDecryptJsonData(EncryptAndDecryptExecutor executor, EncryptionAndDecryptionOptions options, String action) {
        String jsonString = "";
        if (ENCRYPTION_ACTION.equals(action)) {
            jsonString = options.getRawPayload();
        }
        if (DECRYPTION_ACTION.equals(action)) {
            jsonString = options.getSecuredPayload();
        }

        // 1. Verify if JSON is valid
        JsonNode rootNode;
        try {
            rootNode = objectMapper.readTree(jsonString);
        } catch (Exception e) {
            throw new EncryptionException("Invalid JSON string", e);
        }

        // 2. Recursive processing of all fields
        JsonNode processedNode = encryptAndDecryptNode(rootNode, executor, options, action);

        // Backfill original value
        if (ENCRYPTION_ACTION.equals(action)) {
            options.setRawPayload(jsonString);
        }
        if (DECRYPTION_ACTION.equals(action)) {
            options.setSecuredPayload(jsonString);
        }

        // 3. Return the processed JSON string
        try {
            return objectMapper.writeValueAsString(processedNode);
        } catch (Exception ex) {
            throw new EncryptionException("Failed to write processed JSON", ex);
        }
    }

    /**
     * Recursive processing of JSON nodes
     */
    private JsonNode encryptAndDecryptNode(JsonNode node, EncryptAndDecryptExecutor executor, EncryptionAndDecryptionOptions options, String action) {
        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            ObjectNode newObjectNode = objectMapper.createObjectNode();

            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                newObjectNode.set(field.getKey(), encryptAndDecryptNode(field.getValue(), executor, options, action));
            }
            return newObjectNode;

        } else if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            ArrayNode newArrayNode = objectMapper.createArrayNode();

            for (JsonNode element : arrayNode) {
                newArrayNode.add(encryptAndDecryptNode(element, executor, options, action));
            }
            return newArrayNode;

        } else if (node.isNull()) {
            // Other types (such as null) remain unchanged
            return node;
        } else {
            return encryptAndDecryptJson(node, executor, options, action);
        }
    }

    private JsonNode encryptAndDecryptJson(JsonNode jsonNode, EncryptAndDecryptExecutor executor, EncryptionAndDecryptionOptions options, String action) {
        if (options == null) {
            throw new EncryptionException("Encryption and decryption info cannot be null");
        }
        if (jsonNode == null || jsonNode.isNull()) {
            return jsonNode;
        }

        if (ENCRYPTION_ACTION.equals(action)) {
            Map<String, String> metadata = new HashMap<>();
            String originalType = getValueType(jsonNode);
            String valueStr = jsonNode.asText();
            metadata.put("type", originalType);
            metadata.put("value", valueStr);
            try {
                String metadataStr = objectMapper.writeValueAsString(metadata);
                // Encrypt basic types (numbers, boolean values) after converting them to strings
                options.setRawPayload(metadataStr);
                String encryptedValue = executor.encrypt(options);
                return new TextNode(encryptedValue);
            } catch (Exception ex) {
                throw new EncryptionException("encrypt node fail", ex);
            }
        }

        if (DECRYPTION_ACTION.equals(action)) {
            options.setSecuredPayload(jsonNode.asText());
            try {
                String metadataStr = executor.decrypt(options);
                var metadata = objectMapper.readValue(metadataStr, Map.class);
                String type = String.valueOf(metadata.get("type"));
                String valueStr = String.valueOf(metadata.get("value"));
                return getValueNade(type, valueStr);
            } catch (Exception ex) {
                throw new EncryptionException("decrypt node fail", ex);
            }
        }
        return jsonNode;
    }

    private String encryptAndDecryptString(EncryptAndDecryptExecutor executor, EncryptionAndDecryptionOptions options, String action) {
        if (options == null) {
            throw new EncryptionException("Encryption and decryption info cannot be null");
        }

        if (ENCRYPTION_ACTION.equals(action)) {
            if (options.getRawPayload() == null || options.getRawPayload().isEmpty()) {
                return options.getRawPayload();
            }
            return executor.encrypt(options);
        }

        if (DECRYPTION_ACTION.equals(action)) {
            if (options.getSecuredPayload() == null || options.getSecuredPayload().isEmpty()) {
                return options.getSecuredPayload();
            }
            return executor.decrypt(options);
        }
        throw new EncryptionException("Encryption or decryption action invalid");
    }

    private static String getValueType(JsonNode node) {
        String originalType;
        if (node.isShort()) {
            originalType = "short";
        } else if (node.isInt()) {
            originalType = "int";
        } else if (node.isLong()) {
            originalType = "long";
        } else if (node.isFloat()) {
            originalType = "float";
        } else if (node.isDouble()) {
            originalType = "double";
        } else if (node.isBoolean()) {
            originalType = "boolean";
        } else {
            originalType = "string";
        }
        return originalType;
    }

    private static JsonNode getValueNade(String type, String value) {
        if ("short".equals(type)) {
            return ShortNode.valueOf(Short.parseShort(value));
        } else if ("int".equals(type)) {
            return IntNode.valueOf(Integer.parseInt(value));
        } else if ("long".equals(type)) {
            return LongNode.valueOf(Long.parseLong(value));
        } else if ("float".equals(type)) {
            return FloatNode.valueOf(Float.parseFloat(value));
        } else if ("double".equals(type)) {
            return DoubleNode.valueOf(Double.parseDouble(value));
        } else if ("boolean".equals(type)) {
            return BooleanNode.valueOf(Boolean.parseBoolean(value));
        } else {
            return TextNode.valueOf(value);
        }
    }

    /**
     * generate a key pair for encryption and decryption
     *
     * @param options the options of the algorithm to use for encryption and decryption
     * @return the key pair
     */
    public static EncryptionKeyPair generateEncryptionKeyPair(GenerateKeyPairOptions options) {
        return EncryptionUtils.getInstance().doGenerateKeyPair(options);
    }

    /**
     * Encrypts the given plaintext using the specified encryption method.
     *
     * @param piiSecuredInfo the encryption and decryption options with plaintext
     * @return processed PiiSecuredInfo with base64 encrypted ciphertext
     */
    public static PiiSecuredInfo encrypt(PiiSecuredInfo piiSecuredInfo, String rawPayload) {
        EncryptionAndDecryptionOptions options = EncryptionAndDecryptionOptions.withPiiSecuredInfo(piiSecuredInfo);
        options.setRawPayload(rawPayload);
        EncryptionUtils.getInstance().doEncryptAndDecrypt(options, ENCRYPTION_ACTION);

        piiSecuredInfo.setInitiatorKeyInfo(options.getInitiatorKeyInfo());
        piiSecuredInfo.setReceiverKeyInfo(options.getReceiverKeyInfo());
        piiSecuredInfo.setSecretAlgorithm(options.getAlgorithmType());
        piiSecuredInfo.setPiiSecretFormatType(options.getEncryptionFormatType());
        piiSecuredInfo.setEncryptionParams(options.getEncryptionParams());
        piiSecuredInfo.setSecuredPayload(options.getSecuredPayload());
        return piiSecuredInfo;
    }

    /**
     * Decrypts the given ciphertext using the specified encryption method.
     *
     * @param piiSecuredInfo the encryption and decryption options with base64 encrypted ciphertext
     * @return decrypt plaintext
     */
    public static String decrypt(PiiSecuredInfo piiSecuredInfo) {
        EncryptionAndDecryptionOptions options = EncryptionAndDecryptionOptions.withPiiSecuredInfo(piiSecuredInfo);
        options.setSecuredPayload(piiSecuredInfo.getSecuredPayload());
        EncryptionUtils.getInstance().doEncryptAndDecrypt(options, DECRYPTION_ACTION);

        piiSecuredInfo.setInitiatorKeyInfo(options.getInitiatorKeyInfo());
        piiSecuredInfo.setReceiverKeyInfo(options.getReceiverKeyInfo());
        piiSecuredInfo.setSecretAlgorithm(options.getAlgorithmType());
        piiSecuredInfo.setPiiSecretFormatType(options.getEncryptionFormatType());
        piiSecuredInfo.setSecuredPayload(options.getSecuredPayload());
        return options.getRawPayload();
    }
}
