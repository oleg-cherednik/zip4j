package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.os.ExtendedTimestampExtraFieldReader;
import ru.olegcherednik.zip4jvm.io.readers.os.InfoZipNewUnixExtraFieldReader;
import ru.olegcherednik.zip4jvm.io.readers.os.InfoZipOldUnitExtraFieldReader;
import ru.olegcherednik.zip4jvm.io.readers.os.NtfsTimestampExtraFieldReader;
import ru.olegcherednik.zip4jvm.model.AesExtraFieldRecord;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.os.ExtendedTimestampExtraFieldRecord;
import ru.olegcherednik.zip4jvm.model.os.InfoZipNewUnixExtraFieldRecord;
import ru.olegcherednik.zip4jvm.model.os.InfoZipOldUnixExtraFieldRecord;
import ru.olegcherednik.zip4jvm.model.os.NtfsTimestampExtraFieldRecord;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_ENTRY_SIZE;
import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_LOCAL_FILE_HEADER_OFFS;
import static ru.olegcherednik.zip4jvm.model.ZipModel.MAX_TOTAL_DISKS;

/**
 * @author Oleg Cherednik
 * @since 14.04.2019
 */
@RequiredArgsConstructor
public class ExtraFieldReader implements Reader<ExtraField> {

    private final int size;
    protected final Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> readers;

    public static Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> getReaders(CentralDirectory.FileHeader fileHeader) {
        boolean uncompressedSize = fileHeader.getUncompressedSize() == MAX_ENTRY_SIZE;
        boolean compressedSize = fileHeader.getCompressedSize() == MAX_ENTRY_SIZE;
        boolean offs = fileHeader.getLocalFileHeaderOffs() == MAX_LOCAL_FILE_HEADER_OFFS;
        boolean disk = fileHeader.getDisk() == MAX_TOTAL_DISKS;
        return getReaders(uncompressedSize, compressedSize, offs, disk);
    }

    public static Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> getReaders(LocalFileHeader localFileHeader) {
        boolean uncompressedSize = localFileHeader.getUncompressedSize() == MAX_ENTRY_SIZE;
        boolean compressedSize = localFileHeader.getCompressedSize() == MAX_ENTRY_SIZE;
        return getReaders(uncompressedSize, compressedSize, false, false);
    }

    private static Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> getReaders(boolean uncompressedSize, boolean compressedSize,
            boolean offs, boolean disk) {
        Map<Integer, Function<Integer, Reader<? extends ExtraField.Record>>> map = new HashMap<>();

        map.put(Zip64.ExtendedInfo.SIGNATURE, size -> new Zip64Reader.ExtendedInfo(size, uncompressedSize, compressedSize, offs, disk));
        map.put(AesExtraFieldRecord.SIGNATURE, AesExtraDataRecordReader::new);
        map.put(NtfsTimestampExtraFieldRecord.SIGNATURE, NtfsTimestampExtraFieldReader::new);
        map.put(InfoZipOldUnixExtraFieldRecord.SIGNATURE, InfoZipOldUnitExtraFieldReader::new);
        map.put(InfoZipNewUnixExtraFieldRecord.SIGNATURE, InfoZipNewUnixExtraFieldReader::new);
        map.put(ExtendedTimestampExtraFieldRecord.SIGNATURE, ExtendedTimestampExtraFieldReader::new);
        return map;
    }

    @Override
    public final ExtraField read(DataInput in) throws IOException {
        return size > 0 ? readExtraField(in) : ExtraField.NULL;
    }

    protected ExtraField readExtraField(DataInput in) throws IOException {
        ExtraField.Builder builder = ExtraField.builder();
        long offsMax = in.getOffs() + size;

        while (in.getOffs() < offsMax)
            builder.addRecord(getExtraFieldRecordReader().read(in));

        return builder.build();
    }

    protected ExtraFieldRecordReader getExtraFieldRecordReader() {
        return new ExtraFieldRecordReader(readers);
    }

}
