package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.strong.EncryptionAlgorithm;
import ru.olegcherednik.zip4jvm.crypto.strong.HashAlgorithm;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.Version;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.realBigZip64;

/**
 * @author Oleg Cherednik
 * @since 22.08.2019
 */
public class Zip64Reader implements Reader<Zip64> {

    @Override
    public final Zip64 read(DataInput in) throws IOException {
        if (findCentralDirectoryLocatorSignature(in)) {
            Zip64.EndCentralDirectoryLocator locator = readEndCentralDirectoryLocator(in);
            findCentralDirectorySignature(locator.getOffs(), in);
            Zip64.EndCentralDirectory dir = readEndCentralDirectory(in);
            return Zip64.of(locator, dir);
        }

        return Zip64.NULL;
    }

    private static boolean findCentralDirectoryLocatorSignature(DataInput in) throws IOException {
        long offs = in.getOffs() - Zip64.EndCentralDirectoryLocator.SIZE;

        if (offs < 0)
            return false;

        in.seek(offs);

        if (in.readDwordSignature() != Zip64.EndCentralDirectoryLocator.SIGNATURE)
            return false;

        in.backward(in.dwordSignatureSize());
        return true;
    }

    private static void findCentralDirectorySignature(long offs, DataInput in) throws IOException {
        in.seek(offs);

        if (in.readDwordSignature() != Zip64.EndCentralDirectory.SIGNATURE)
            throw new Zip4jvmException("invalid zip64 end of central directory");

        in.backward(in.dwordSignatureSize());
    }

    protected Zip64.EndCentralDirectoryLocator readEndCentralDirectoryLocator(DataInput in) throws IOException {
        return new Zip64Reader.EndCentralDirectoryLocator().read(in);
    }

    protected Zip64.EndCentralDirectory readEndCentralDirectory(DataInput in) throws IOException {
        return new Zip64Reader.EndCentralDirectory().read(in);
    }

    private static final class EndCentralDirectoryLocator {

        public Zip64.EndCentralDirectoryLocator read(DataInput in) throws IOException {
            in.skip(in.dwordSignatureSize());

            Zip64.EndCentralDirectoryLocator locator = new Zip64.EndCentralDirectoryLocator();
            locator.setMainDisk(in.readDword());
            locator.setOffs(in.readQword());
            locator.setTotalDisks(in.readDword());

            realBigZip64(locator.getOffs(), "zip64.centralDirectoryOffs");

            return locator;
        }

    }

    private static final class EndCentralDirectory {

        public Zip64.EndCentralDirectory read(DataInput in) throws IOException {
            in.skip(in.dwordSignatureSize());

            Zip64.EndCentralDirectory dir = new Zip64.EndCentralDirectory();
            long endCentralDirectorySize = in.readQword();
            dir.setEndCentralDirectorySize(endCentralDirectorySize);
            dir.setVersionMadeBy(Version.of(in.readWord()));
            dir.setVersionToExtract(Version.of(in.readWord()));
            dir.setTotalDisks(in.readDword());
            dir.setMainDisk(in.readDword());
            dir.setDiskEntries(in.readQword());
            dir.setTotalEntries(in.readQword());
            dir.setCentralDirectorySize(in.readQword());
            dir.setCentralDirectoryOffs(in.readQword());
            dir.setExtensibleDataSector(new ExtensibleDataSector()in.readBytes((int)endCentralDirectorySize - Zip64.EndCentralDirectory.SIZE));

            realBigZip64(dir.getCentralDirectoryOffs(), "centralDirectoryOffs");
            realBigZip64(dir.getTotalEntries(), "totalEntries");

            return dir;
        }

    }

    @RequiredArgsConstructor
    public static final class ExtendedInfo implements Reader<Zip64.ExtendedInfo> {

        private final int size;
        private final boolean uncompressedSizeExists;
        private final boolean compressedSizeExists;
        private final boolean offsLocalHeaderRelativeExists;
        private final boolean diskExists;

        @Override
        public Zip64.ExtendedInfo read(DataInput in) throws IOException {
            long offs = in.getOffs();

            Zip64.ExtendedInfo extendedInfo = readExtendedInfo(in);

            if (in.getOffs() - offs != size) {
                // section exists, but not need to read it; all data is in FileHeader
                extendedInfo = Zip64.ExtendedInfo.NULL;
                in.seek(offs + size);
            }

            return extendedInfo;
        }

        private Zip64.ExtendedInfo readExtendedInfo(DataInput in) throws IOException {
            long uncompressedSize = uncompressedSizeExists ? in.readQword() : ExtraField.NO_DATA;
            long compressedSize = compressedSizeExists ? in.readQword() : ExtraField.NO_DATA;
            long offsLocalHeaderRelative = offsLocalHeaderRelativeExists ? in.readQword() : ExtraField.NO_DATA;
            long disk = diskExists ? in.readDword() : ExtraField.NO_DATA;

            return Zip64.ExtendedInfo.builder()
                                     .uncompressedSize(uncompressedSize)
                                     .compressedSize(compressedSize)
                                     .localFileHeaderOffs(offsLocalHeaderRelative)
                                     .disk(disk).build();
        }

        @Override
        public String toString() {
            return "ZIP64";
        }

    }

    @RequiredArgsConstructor
    static final class ExtensibleDataSector implements Reader<Zip64.ExtensibleDataSector> {

        private final int size;

        @Override
        public Zip64.ExtensibleDataSector read(DataInput in) throws IOException {
            if (size == 0)
                return Zip64.ExtensibleDataSector.NULL;

            long offs = in.getOffs();

            Zip64.ExtensibleDataSector extensibleDataSector = readExtensibleDataSector(in);

            if (in.getOffs() - offs != size)
                throw new Zip4jvmException("Incorrect ExtensibleDataSector");

            return extensibleDataSector;
        }

        private static Zip64.ExtensibleDataSector readExtensibleDataSector(DataInput in) throws IOException {
            CompressionMethod compressionMethod = CompressionMethod.parseCode(in.readWord());
            long compressedSize = in.readQword();
            long uncompressedSize = in.readQword();
            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.parseCode(in.readWord());
            int bitLength = in.readWord();
            int flags = in.readWord();
            HashAlgorithm hashAlgorithm = HashAlgorithm.parseCode(in.readWord());
            int hashLength = in.readWord();
            byte[] hashData = in.readBytes(hashLength);

            return Zip64.ExtensibleDataSector.builder()
                                             .compressionMethod(compressionMethod)
                                             .compressedSize(compressedSize)
                                             .uncompressedSize(uncompressedSize)
                                             .encryptionAlgorithm(encryptionAlgorithm)
                                             .bitLength(bitLength)
                                             .flags(flags)
                                             .hashAlgorithm(hashAlgorithm)
                                             .hashLength(hashLength)
                                             .hashData(hashData).build();
        }

    }

}
