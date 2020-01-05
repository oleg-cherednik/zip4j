package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

/**
 * see 7.3.4
 *
 * @author Oleg Cherednik
 * @since 09.10.2019
 */
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public enum HashAlgorithm {

    NONE(0x0),
    CRC32(0x1),
    MD5(0x8003),
    SHA1(0x8004),
    RIPEMD160(0x0807),
    SHA256(0x800C),
    SHA384(0x800D),
    SHA512(0x800E);

    private final int code;

    public static HashAlgorithm parseCode(int code) {
        for (HashAlgorithm hashAlgorithm : values())
            if (hashAlgorithm.code == code)
                return hashAlgorithm;
        throw new EnumConstantNotPresentException(HashAlgorithm.class, "code: " + code);
    }

}
