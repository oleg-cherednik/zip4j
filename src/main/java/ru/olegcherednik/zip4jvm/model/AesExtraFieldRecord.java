package ru.olegcherednik.zip4jvm.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang.StringUtils;
import ru.olegcherednik.zip4jvm.crypto.aes.AesStrength;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Optional;

@Getter
public final class AesExtraFieldRecord implements ExtraField.Record {

    public static final AesExtraFieldRecord NULL = builder().build();

    public static final int SIGNATURE = 0x9901;
    public static final int SIZE = 2 + 2 + 2 + 2 + 1 + 2;   // size:11

    // size:2 - signature (0x9901)
    // size:2
    private final int dataSize;
    // size:2
    private final int versionNumber;
    // size:2
    private final String vendor;
    // size:1
    private final AesStrength strength;
    // size:2
    private final CompressionMethod compressionMethod;

    public static Builder builder() {
        return new Builder();
    }

    private AesExtraFieldRecord(Builder builder) {
        dataSize = builder.dataSize;
        versionNumber = builder.versionNumber;
        vendor = builder.vendor;
        strength = builder.strength;
        compressionMethod = builder.compressionMethod;
    }

    public byte[] getVendor(Charset charset) {
        return vendor == null ? null : vendor.getBytes(charset);
    }

    @Override
    public int getBlockSize() {
        return this == NULL ? 0 : SIZE;
    }

    @Override
    public int getSignature() {
        return SIGNATURE;
    }

    @Override
    public boolean isNull() {
        return this == NULL;
    }

    @Override
    public String getTitle() {
        return "AES Encryption Tag";
    }

    @Override
    public String toString() {
        return isNull() ? "<null>" : "strength:" + strength.getSize() + ", compression:" + compressionMethod.name();
    }

    @Override
    public void write(DataOutput out) throws IOException {
        if (this == NULL)
            return;

        out.writeWordSignature(SIGNATURE);
        out.writeWord(dataSize);
        out.writeWord(versionNumber);
        out.writeBytes(getVendor(Charsets.UTF_8));
        out.writeBytes((byte)strength.getCode());
        out.writeWord(compressionMethod.getCode());
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class Builder {

        private int dataSize = ExtraField.NO_DATA;
        private int versionNumber = ExtraField.NO_DATA;
        private String vendor;
        private AesStrength strength = AesStrength.NULL;
        private CompressionMethod compressionMethod = CompressionMethod.DEFLATE;

        public AesExtraFieldRecord build() {
            return new AesExtraFieldRecord(this);
        }

        public Builder dataSize(int dataSize) {
            this.dataSize = dataSize;
            return this;
        }

        public Builder versionNumber(int versionNumber) {
            this.versionNumber = versionNumber;
            return this;
        }

        public Builder vendor(String vendor) {
            if (StringUtils.length(vendor) > 2)
                throw new Zip4jvmException("AESExtraDataRecord.vendor should be maximum 2 characters");

            this.vendor = vendor;
            return this;
        }

        public Builder strength(AesStrength strength) {
            this.strength = Optional.ofNullable(strength).orElse(AesStrength.NULL);
            return this;
        }

        public Builder compressionMethod(CompressionMethod compressionMethod) {
            this.compressionMethod = Optional.ofNullable(compressionMethod).orElse(CompressionMethod.DEFLATE);
            return this;
        }
    }

}
