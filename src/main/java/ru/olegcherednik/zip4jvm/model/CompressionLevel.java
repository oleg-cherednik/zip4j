package ru.olegcherednik.zip4jvm.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * see 4.4.4
 *
 * @author Oleg Cherednik
 * @since 09.03.2019
 */
@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public enum CompressionLevel {
    SUPER_FAST(1, "superfast"),
    FAST(3, "fast"),
    NORMAL(6, "normal"),
    MAXIMUM(9, "maximum");

    private final int code;
    private final String title;

}
