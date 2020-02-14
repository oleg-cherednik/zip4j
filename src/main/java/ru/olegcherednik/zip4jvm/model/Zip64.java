package ru.olegcherednik.zip4jvm.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 26.04.2019
 */
@Getter
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class Zip64 {

    public static final Zip64 NULL = new Zip64(null, null);
    public static final int LIMIT_WORD = 0xFFFF;
    public static final long LIMIT_DWORD = 0xFFFF_FFFFL;

    private final EndCentralDirectoryLocator endCentralDirectoryLocator;
    private final EndCentralDirectory endCentralDirectory;

    public static Zip64 of(EndCentralDirectoryLocator endCentralDirectoryLocator, EndCentralDirectory endCentralDirectory) {
        return endCentralDirectoryLocator == null || endCentralDirectory == null ? NULL : new Zip64(endCentralDirectoryLocator, endCentralDirectory);
    }

    @Override
    public String toString() {
        return this == NULL ? "<null>" : super.toString();
    }

    /** see 4.3.15 */
    @Getter
    @Setter
    public static class EndCentralDirectoryLocator {

        public static final int SIGNATURE = 0x07064B50;

        // size (20) with comment length = 0
        public static final int SIZE = 4 + 4 + 8 + 4;

        // size:4 - signature (0x06054b50)
        // size:4 - number of the disk with the start of the zip64 end of central directory
        private long mainDisk;
        // size:8 - relative offset of the Zip64.EndCentralDirectory
        private long offs;
        // size:4 - total number of disks
        private long totalDisks;

    }

    /** see 4.3.14 */
    @Getter
    @Setter
    public static class EndCentralDirectory {

        public static final int SIGNATURE = 0x06064B50;
        // size (44) with extensibleDataSector length = 0
        public static final int SIZE = 2 + 2 + 4 + 4 + 8 + 8 + 8 + 8;

        // size:4 - signature (0x06064b50)
        // size:8 - directory record (n)
        private long endCentralDirectorySize;
        // size:2 - version made by
        private Version versionMadeBy = Version.NULL;
        // size:2 - version needed to extractEntries
        private Version versionToExtract = Version.NULL;
        // size:4 - number of this disk
        private long totalDisks;
        // size:4 - number of the disk with the start of the central directory
        private long mainDisk;
        // size:8 - total number of entries in the central directory on this disk
        private long diskEntries;
        // size:8 - total number of entries in the central directory
        private long totalEntries;
        // size:8 - size of the central directory
        private long centralDirectorySize;
        // size:8 - offs of CentralDirectory in startDiskNumber
        private long centralDirectoryOffs;
        // size:n-44 - extensible data sector
        private byte[] extensibleDataSector = ArrayUtils.EMPTY_BYTE_ARRAY;

    }

    /** see 4.5.3 */
    @Getter
    public static final class ExtendedInfo implements ExtraField.Record {

        public static final ExtendedInfo NULL = new ExtendedInfo(new Builder());

        public static final int SIGNATURE = 0x0001;
        public static final int SIZE_FIELD = 2 + 2; // 4 bytes: signature + size

        public static Builder builder() {
            return new Builder();
        }

        // size:2 - tag for this "extra" block type (ZIP64 = 0x001)
        // size:2 - size of this "extra" block
        // size:8 - original uncompressed file size
        private final long uncompressedSize;
        // size:8 - size of compressed data
        private final long compressedSize;
        // size:8 - offset of local header record
        private final long localFileHeaderOffs;
        // size:4 - number of the disk on which  this file starts
        private final long disk;

        private ExtendedInfo(Builder builder) {
            uncompressedSize = builder.uncompressedSize;
            compressedSize = builder.compressedSize;
            localFileHeaderOffs = builder.localFileHeaderOffs;
            disk = builder.disk;
        }

        public int getDataSize() {
            int size = 0;

            if (uncompressedSize != ExtraField.NO_DATA)
                size += 8;
            if (compressedSize != ExtraField.NO_DATA)
                size += 8;
            if (localFileHeaderOffs != ExtraField.NO_DATA)
                size += 8;
            if (disk != ExtraField.NO_DATA)
                size += 4;

            return size;
        }

        @Override
        public int getBlockSize() {
            return isNull() ? 0 : getDataSize() + SIZE_FIELD;
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
            return "Zip64 Extended Information";
        }

        @Override
        public String toString() {
            return isNull() ? "<null>" : super.toString();
        }

        @Override
        public void write(DataOutput out) throws IOException {
            if (isNull())
                return;

            out.writeWordSignature(SIGNATURE);
            out.writeWord(getDataSize());

            if (getUncompressedSize() != ExtraField.NO_DATA)
                out.writeQword(getUncompressedSize());
            if (getCompressedSize() != ExtraField.NO_DATA)
                out.writeQword(getCompressedSize());
            if (getLocalFileHeaderOffs() != ExtraField.NO_DATA)
                out.writeQword(getLocalFileHeaderOffs());
            if (getDisk() != ExtraField.NO_DATA)
                out.writeDword(getDisk());
        }

        @NoArgsConstructor(access = AccessLevel.PRIVATE)
        public static final class Builder {

            private long uncompressedSize = ExtraField.NO_DATA;
            private long compressedSize = ExtraField.NO_DATA;
            private long localFileHeaderOffs = ExtraField.NO_DATA;
            private long disk = ExtraField.NO_DATA;

            public ExtendedInfo build() {
                if (uncompressedSize == ExtraField.NO_DATA && compressedSize == ExtraField.NO_DATA
                        && localFileHeaderOffs == ExtraField.NO_DATA && disk == ExtraField.NO_DATA)
                    return NULL;
                return new ExtendedInfo(this);
            }

            public Builder uncompressedSize(long uncompressedSize) {
                this.uncompressedSize = uncompressedSize;
                return this;
            }

            public Builder compressedSize(long compressedSize) {
                this.compressedSize = compressedSize;
                return this;
            }

            public Builder localFileHeaderOffs(long localFileHeaderOffs) {
                this.localFileHeaderOffs = localFileHeaderOffs;
                return this;
            }

            public Builder disk(long disk) {
                this.disk = disk;
                return this;
            }
        }

    }

}
