package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.Getter;
import lombok.Setter;

/**
 * @author Oleg Cherednik
 * @since 11.10.2019
 */
@Getter
@Setter
public class DecryptionHeader {

    // TODO if 0 - then CRC32 + 64bit FileSize should be used to decrypt daa
    // size:2 - size of initialization vector (n)
    private int ivSize;
    // size:n - initialization vector for this file
    private byte[] iv;
    // size:4 - size of remaining decryption header data
    private long size;
    private DecryptionInfo decryptionInfo;

}
