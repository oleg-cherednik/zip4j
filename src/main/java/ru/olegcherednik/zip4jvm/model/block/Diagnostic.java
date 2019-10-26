package ru.olegcherednik.zip4jvm.model.block;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.utils.function.LocalSupplier;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Oleg Cherednik
 * @since 19.10.2019
 */
@Getter
@Setter
public final class Diagnostic {

    private final Block endCentralDirectory = new Block();
    private Zip64 zip64 = Zip64.NULL;
    private final CentralDirectory centralDirectory = new CentralDirectory();
    private final ZipEntryBlock zipEntryBlock = new ZipEntryBlock();

    public void addZip64() {
        zip64 = new Zip64();
    }

    @Getter
    @Setter
    public static final class Zip64 {

        public static final Zip64 NULL = new Zip64();

        private final Block endCentralDirectoryLocator = new Block();
        private final Block endCentralDirectory = new Block();

    }

    @Getter
    @Setter
    public static final class CentralDirectory extends Block {

        public static final CentralDirectory NULL = new CentralDirectory();

        private Block digitalSignature = Block.NULL;

        private final Map<String, FileHeader> fileHeaders = new LinkedHashMap<>();

        @Setter(AccessLevel.NONE)
        private FileHeader fileHeader = FileHeader.NULL;

        public void addDigitalSignature() {
            digitalSignature = new Block();
        }

        public void addFileHeader() {
            fileHeader = new FileHeader();
        }

        public void saveFileHeader(String fileName) {
            fileHeaders.put(fileName, fileHeader);
            fileHeader = FileHeader.NULL;
        }

        public FileHeader getFileHeader(String fileName) {
            return fileHeaders.get(fileName);
        }

        @Getter
        @Setter
        public static final class FileHeader extends ExtraFieldBlock {

            public static final FileHeader NULL = new FileHeader();

        }

    }

    @Getter
    @Setter
    public abstract static class ExtraFieldBlock extends Block {

        private ExtraField extraField;

        public void addExtraField() {
            extraField = new ExtraField();
        }
    }


    @Getter
    @Setter
    public static final class ExtraField extends Block {

        private final Map<Integer, Block> records = new LinkedHashMap<>();

        @Setter(AccessLevel.NONE)
        private Block record;

        public void addRecord() {
            record = new Block();
        }

        public void saveRecord(int signature) {
            records.put(signature, record);
            record = null;
        }

        public Block getRecord(int signature) {
            return records.get(signature);
        }

    }

    @Getter
    @Setter
    public static final class ZipEntryBlock {

        public static final ZipEntry NULL = new ZipEntry();

        private final Map<String, LocalFileHeader> localFileHeaders = new LinkedHashMap<>();
        private final Map<String, EncryptionHeader> encryptionHeaders = new LinkedHashMap<>();
        private final Map<String, Block> dataDescriptors = new LinkedHashMap<>();

        @Setter(AccessLevel.NONE)
        private LocalFileHeader localFileHeader = LocalFileHeader.NULL;

        public void addLocalFileHeader() {
            localFileHeader = new LocalFileHeader();
        }

        public void saveLocalFileHeader(String fileName) {
            localFileHeaders.put(fileName, localFileHeader);
            localFileHeader = LocalFileHeader.NULL;
        }

        public void saveEncryptionHeader(String fileName, EncryptionHeader encryptionHeader) {
            encryptionHeaders.put(fileName, encryptionHeader);
        }

        public void saveDataDescriptor(String fileName, Block block) {
            dataDescriptors.put(fileName, block);
        }

        public LocalFileHeader getLocalFileHeader(String fileName) {
            return localFileHeaders.get(fileName);
        }

        public EncryptionHeader getEncryptionHeader(String fileName) {
            return encryptionHeaders.get(fileName);
        }

        public Block getDataDescriptor(String fileName) {
            return dataDescriptors.get(fileName);
        }

        @Getter
        @Setter
        public static final class LocalFileHeader extends ExtraFieldBlock {

            public static final LocalFileHeader NULL = new LocalFileHeader();

            private long disk;

        }

        public interface EncryptionHeader {

        }

    }

    @Getter
    @Setter
    public static final class ByteArrayBlock extends Block {

        private byte[] data;

        @Override
        public <T> T calc(DataInput in, LocalSupplier<T> task) throws IOException {
            T res = super.calc(in, task);
            data = (byte[])res;
            return res;
        }
    }

    @Getter
    @Setter
    public static final class ZipEntry extends Block {

        public static final ZipEntry NULL = new ZipEntry();

        private final Map<String, LocalFileHeader> localFileHeaders = new LinkedHashMap<>();

        @Setter(AccessLevel.NONE)
        private LocalFileHeader localFileHeader = LocalFileHeader.NULL;


        public void createLocalFileHeader() {
            localFileHeader = new LocalFileHeader();
        }

        public void saveLOcalFileHeader(String fileName) {
            localFileHeaders.put(fileName, localFileHeader);
            localFileHeader = LocalFileHeader.NULL;
        }

        public LocalFileHeader getLocalFileHeader(String fileName) {
            return localFileHeaders.get(fileName);
        }

        @Getter
        @Setter
        public static final class LocalFileHeader extends Block {

            public static final LocalFileHeader NULL = new LocalFileHeader();

            private ExtraField extraField;

            public void addExtraField() {
                extraField = new ExtraField();
            }
        }

    }

}
