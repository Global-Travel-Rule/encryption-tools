/*
 * Copyright (c) 2022-2025 Global Travel Rule • globaltravelrule.com
 * License that can be found in the LICENSE file.
 * Author: Global Travel Rule developer
 * Created on: 2025/7/27 16:35
 */

package com.globaltravelrule.encryption.core.options;

import java.util.Date;

/**
 * encryption key pair options
 *
 * @author Global Travel Rule developer
 * @version 1.0.1
 * @since 1.0.1
 */
public class GenerateKeyPairOptions {

    private String algorithmType;

    private String keyFormat;

    /**
     * subject DN
     * example: CN=Dave, OU=JavaSoft, O=Sun Microsystems, C=US
     */
    private String subjectDN;

    /**
     * default current time
     */
    private Date startDate;

    /**
     * default current time and one year
     */
    private Date endDate;

    public GenerateKeyPairOptions() {
    }

    public GenerateKeyPairOptions(String algorithmType) {
        this.algorithmType = algorithmType;
    }

    public String getAlgorithmType() {
        return algorithmType;
    }

    public void setAlgorithmType(String algorithmType) {
        this.algorithmType = algorithmType;
    }

    public String getKeyFormat() {
        return keyFormat;
    }

    public void setKeyFormat(String keyFormat) {
        this.keyFormat = keyFormat;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }
}
