package com.github.lisama569.containerimageadmissionservicejava.domain;

public enum Severity {
    NONE(0),
    UNKNOWN(1),
    LOW(2),
    MEDIUM(3),
    HIGH(4),
    CRITICAL(5);

    private final int level;

    Severity(int level) {
        this.level = level;
    }

    public int level() {
        return level;
    }
}
