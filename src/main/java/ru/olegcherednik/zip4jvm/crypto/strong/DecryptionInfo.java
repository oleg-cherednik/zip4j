package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.util.Collections;
import java.util.List;

/**
 * @author Oleg Cherednik
 * @since 05.01.2020
 */
@Getter
@Setter
public class DecryptionInfo {

    // size:2 - version of this record
    private int version;
    // size:2 - encryption algorithm identifier
    private EncryptionAlgorithm encryptionAlgorithm;
    // size:2 - bit length of encryption key
    private int bitLength;
    // size:2 - Processing flags
    private Flags flags;
    // size:2 - size of Encrypted Random Data (m)
    private int encryptedRandomDataSize;
    // size:m - encrypted random data
    private byte[] encryptedRandomData;
    // size:4 - number of recipients (n)
    private long recipientCount;
    // size:2 - hash algorithm to be used to calculate Public Key hash (absent for password based encryption)
    private int hashAlgorithm;
    // size:2 - size of Public Key hash (absent for password based encryption) (p)
    private int hashSize;
    // size:n - Recipient List Element (absent for password based encryption)
    private List<Recipient> recipients = Collections.emptyList();
    // size:2 - size of initialization vector (k)
    private int passwordValidationDataSize;
    // size:k - password validation data
    private byte[] passwordValidationData;
    // size:4 - checksum of password validation data
    private long crc32;

    @RequiredArgsConstructor(access = AccessLevel.PACKAGE)
    public enum Flags {
        PASSWORD_KEY(0x1),
        CERTIFICATE_KEY(0x2),
        COMBO_KEY(0x3),
        DOUBLE_SEED_KEY(0x7),
        DOUBLE_DATA_KEY(0xF),
        MASTER_KEY_3DES(0x4000);

        private final int code;

        public static Flags parseCode(int code) {
            for (Flags flags : values())
                if (flags.code == code)
                    return flags;
            throw new EnumConstantNotPresentException(Flags.class, "code: " + code);
        }
    }

    @Getter
    @Setter
    public static final class Recipient {

        // size:2 = combined size of followed fields (w)
        private int size;
        // size:p - hash of Public Key
        private byte[] hash;
        // size:(w - p) - Simple Key Blob
        private byte[] simpleKeyBlob;

    }

}
