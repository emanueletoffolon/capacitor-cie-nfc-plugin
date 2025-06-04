package com.yourcompany.plugins.cienfcplugin;

public class CieException extends Exception {
    private String errorCode;

    public CieException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
