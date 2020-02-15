package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.ExtraField;

import java.io.IOException;
import java.util.Optional;

/**
 * see 4.5.12
 *
 * @author Oleg Cherednik
 * @since 09.10.2019
 */
@Getter
public final class StrongEncryptionHeader implements ExtraField.Record {

    public static final StrongEncryptionHeader NULL = builder().build();

    public static final int SIGNATURE = 0x0017;
    public static final int SIZE = 2 + 2 + 2 + 2 + 2 + 2;   // size:12

    // size:2 - tag for this "extra" block type (0x0017)
    // size:2 - size of data that follows (n)
    private final int size;
    // size:2 - the data format identifier
    private final int format;
    // size:2 - encryption algorithm
    private final EncryptionAlgorithm encryptionAlgorithm;
    // size:2 - encryption key length
    private final int bitLength;
    // size:2 - encryption flags
    private final int flags;
    // size:n-8 - certificate decryption extra field data
    private final byte[] certData;

    public static Builder builder() {
        return new Builder();
    }

    private StrongEncryptionHeader(Builder builder) {
        size = builder.size;
        format = builder.format;
        encryptionAlgorithm = builder.encryptionAlgorithm;
        bitLength = builder.bitLength;
        flags = builder.flags;
        certData = null;
    }

    @Override
    public int getSignature() {
        return SIGNATURE;
    }

    @Override
    public int getBlockSize() {
        return this == NULL ? 0 : SIZE + size - 8;
    }

    @Override
    public boolean isNull() {
        return this == NULL;
    }

    @Override
    public String getTitle() {
        return null;
    }

    @Override
    public void write(DataOutput out) throws IOException {

    }

    @Override
    public String toString() {
        return this == NULL ? "<null>" : super.toString();
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class Builder {

        private int size;
        private int format = 2;
        private EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.AES_256;
        private int bitLength;
        private int flags;
        private byte[] certData;

        public StrongEncryptionHeader build() {
            return new StrongEncryptionHeader(this);
        }

        public Builder size(int size) {
            this.size = size;
            return this;
        }

        public Builder format(int format) {
            this.format = format;
            return this;
        }

        public Builder encryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
            this.encryptionAlgorithm = Optional.ofNullable(encryptionAlgorithm).orElse(EncryptionAlgorithm.AES_256);
            return this;
        }

        public Builder bitLength(int bitLength) {
            this.bitLength = bitLength;
            return this;
        }

        public Builder flags(int flags) {
            this.flags = flags;
            return this;
        }

        public Builder certData(byte[] certData) {
            this.certData = ArrayUtils.clone(certData);
            return this;
        }
    }
}
