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
import com.globaltravelrule.encryption.core.options.EncryptAndDecryptOptions;
import com.globaltravelrule.encryption.core.options.EncryptionKeyPair;

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
     * @param algorithmType the encryption algorithm type
     * @return the key pair
     * @throws EncryptionException if the algorithm is not supported or other encryption-related errors occur
     */
    private EncryptionKeyPair doGenerateKeyPair(String algorithmType) {
        EncryptAndDecryptExecutor executor = getCryptionExecutor(algorithmType);
        return executor.generateKeyPair();
    }

    /**
     * Encrypt the plain text using the specified algorithm and options.
     * Decrypt the encrypted text using the specified algorithm and options.
     *
     * @param text    the plain text to be encrypted or decrypted
     * @param options the encryption options
     * @return the encrypted or decrypted text
     */
    private String doEncryptAndDecrypt(String text, EncryptAndDecryptOptions options, String action) {
        EncryptAndDecryptExecutor executor = getCryptionExecutor(options.getAlgorithm());
        if (EncryptionFormat.FULL_JSON_OBJECT_ENCRYPT.getFormat().equals(options.getEncryptFormat())) {
            return encryptAndDecryptString(text, executor, options, action);
        }
        if (EncryptionFormat.JSON_FIELD_ENCRYPT.getFormat().equals(options.getEncryptFormat())) {
            return encryptAndDecryptJsonData(text, executor, options, action);
        }
        if (EncryptionFormat.JSON_FIELD_HASHED.getFormat().equals(options.getEncryptFormat())) {
            return encryptAndDecryptJsonData(text, executor, options, action);
        }
        return encryptAndDecryptString(text, executor, options, action);
    }


    /**
     * Encrypt all strings and basic type fields in JSON strings
     *
     * @param jsonString Original JSON string
     * @param executor   CryptionExecutor instance for encryption
     * @param options    options for encryption and decryption
     * @param action     "encrypt" or "decrypt"
     * @return Encrypted JSON string
     * @throws EncryptionException If JSON is illegal or encryption error occurs
     */
    public String encryptAndDecryptJsonData(String jsonString, EncryptAndDecryptExecutor executor, EncryptAndDecryptOptions options, String action) {
        // 1. Verify if JSON is valid
        JsonNode rootNode;
        try {
            rootNode = objectMapper.readTree(jsonString);
        } catch (Exception e) {
            throw new EncryptionException("Invalid JSON string", e);
        }

        // 2. Recursive processing of all fields
        JsonNode processedNode = encryptAndDecryptNode(rootNode, executor, options, action);

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
    private JsonNode encryptAndDecryptNode(JsonNode node, EncryptAndDecryptExecutor executor, EncryptAndDecryptOptions options, String action) {
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

    private JsonNode encryptAndDecryptJson(JsonNode jsonNode, EncryptAndDecryptExecutor executor, EncryptAndDecryptOptions options, String action) {
        if (options == null) {
            throw new EncryptionException("Encryption and decryption options cannot be null");
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
                String encryptedValue = executor.encrypt(options, metadataStr);
                return new TextNode(encryptedValue);
            } catch (Exception ex) {
                throw new EncryptionException("encrypt node fail", ex);
            }
        }

        if (DECRYPTION_ACTION.equals(action)) {
            String metadataStr = executor.decrypt(options, jsonNode.asText());
            try {
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

    private String encryptAndDecryptString(String textData, EncryptAndDecryptExecutor executor, EncryptAndDecryptOptions options, String action) {
        if (options == null) {
            throw new EncryptionException("Encryption and decryption options cannot be null");
        }

        if (textData == null || textData.isEmpty()) {
            return textData;
        }

        if (ENCRYPTION_ACTION.equals(action)) {
            return executor.encrypt(options, textData);
        }

        if (DECRYPTION_ACTION.equals(action)) {
            return executor.decrypt(options, textData);
        }
        return textData;
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
     * @param algorithmType the type of the algorithm to use for encryption and decryption
     * @return the key pair
     */
    public static EncryptionKeyPair generateEncryptionKeyPair(String algorithmType) {
        return EncryptionUtils.getInstance().doGenerateKeyPair(algorithmType);
    }

    /**
     * Encrypt the plain text using the specified algorithm and options.
     *
     * @param plainText the plain text to be encrypted
     * @param options   the encryption options
     * @return the encrypted text
     */
    public static String encrypt(String plainText, EncryptAndDecryptOptions options) {
        return EncryptionUtils.getInstance().doEncryptAndDecrypt(plainText, options, ENCRYPTION_ACTION);
    }

    /**
     * Decrypt the encrypted text using the specified algorithm and options.
     *
     * @param encryptedText the encrypted text to be decrypted
     * @param options       the decryption options
     * @return the decrypted text
     */
    public static String decrypt(String encryptedText, EncryptAndDecryptOptions options) {
        return EncryptionUtils.getInstance().doEncryptAndDecrypt(encryptedText, options, DECRYPTION_ACTION);
    }
}
