package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.RequiredArgsConstructor;

/**
 * @author Oleg Cherednik
 * @since 10.10.2019
 */
@RequiredArgsConstructor
public enum EncryptionAlgorithm {
    DES(0x6601),
    RC2_PRE_52(0x6602),
    TRIPLE_DES_168(0x6603),
    TRIPLE_DES_192(0x6609),
    AES_128(0x660E),
    AES_192(0x660F),
    AES_256(0x6610),
    RC2(0x6702),
    RC4(0x6801),
    BLOWFISH(0x6720),
    TWOFISH(0x6721),
    UNKNOWN(0xFFFF);

    private final int code;

    public static EncryptionAlgorithm parseCode(int code) {
        for (EncryptionAlgorithm encryptionAlgorithm : values())
            if (encryptionAlgorithm.code == code)
                return encryptionAlgorithm;
        throw new EnumConstantNotPresentException(EncryptionAlgorithm.class, "code: " + code);
    }
}
