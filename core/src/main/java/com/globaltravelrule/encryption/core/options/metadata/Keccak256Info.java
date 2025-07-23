/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/7/22 20:41
 */

package com.globaltravelrule.encryption.core.options.metadata;

/**
 * Keccak256 Algorithm Meta Info
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class Keccak256Info {

    /***
     * salt for hash encryption
     */
    private String salt;

    public Keccak256Info() {

    }

    public Keccak256Info(String salt) {
        this.salt = salt;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
