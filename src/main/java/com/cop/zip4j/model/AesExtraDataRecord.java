package com.cop.zip4j.model;

import com.cop.zip4j.exception.Zip4jException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang.ArrayUtils;

import java.nio.charset.Charset;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class AesExtraDataRecord {

    public static final int SIGNATURE = 0x9901;
    public static final int SIZE = 2 + 2 + 2 + 2 + 1 + 2;   // size:11
    public static final int SIZE_FIELD = 2 + 2; // 4 bytes: signature + size

    // size:2 - signature (0x9901)
    // size:2
    @Builder.Default
    private int dataSize = ExtraField.NO_DATA;
    // size:2
    @Builder.Default
    private int versionNumber = ExtraField.NO_DATA;
    // size:2
    private String vendor;
    // size:1
    @NonNull
    @Builder.Default
    private AesStrength aesStrength = AesStrength.NONE;
    // size:2
    @NonNull
    @Builder.Default
    private CompressionMethod compressionMethod = CompressionMethod.STORE;

    // TODO should be checked on set
    public byte[] getVendor(@NonNull Charset charset) {
        byte[] buf = vendor != null ? vendor.getBytes(charset) : null;

        if (ArrayUtils.getLength(buf) > 2)
            throw new Zip4jException("AESExtraDataRecord.vendor should be maximum 2 characters");

        return buf;
    }

    public int getLength() {
        return SIZE;
    }

    public static final AesExtraDataRecord NULL = new AesExtraDataRecord() {

        private final NullPointerException exception = new NullPointerException("Null object modification: " + getClass().getSimpleName());

        @Override
        public void setDataSize(int dataSize) {
            throw exception;
        }

        @Override
        public void setVersionNumber(int versionNumber) {
            throw exception;
        }

        @Override
        public void setVendor(String vendor) {
            throw exception;
        }

        @Override
        public void setAesStrength(AesStrength aesStrength) {
            throw exception;
        }

        @Override
        public void setCompressionMethod(CompressionMethod compressionMethod) {
            throw exception;
        }

        @Override
        public int getLength() {
            return 0;
        }
    };

}
