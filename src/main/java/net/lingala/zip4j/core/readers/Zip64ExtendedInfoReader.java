package net.lingala.zip4j.core.readers;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.lingala.zip4j.model.ExtraField;
import net.lingala.zip4j.model.Zip64;
import net.lingala.zip4j.io.LittleEndianRandomAccessFile;

import java.io.IOException;

/**
 * see 4.4.8, 4.4.9, 4.4.16, 4.5.3
 *
 * @author Oleg Cherednik
 * @since 14.04.2019
 */
@RequiredArgsConstructor
final class Zip64ExtendedInfoReader {

    private final short signature;
    private final boolean uncompressedSize;
    private final boolean compressedSize;
    private final boolean offs;
    private final boolean diskNumber;

    @NonNull
    public Zip64.ExtendedInfo read(@NonNull LittleEndianRandomAccessFile in) throws IOException {
        if (signature != Zip64.ExtendedInfo.SIGNATURE)
            return Zip64.ExtendedInfo.NULL;

        Zip64.ExtendedInfo res = new Zip64.ExtendedInfo();
        res.setSize(in.readWord());
        res.setUncompressedSize(uncompressedSize ? in.readLong() : ExtraField.NO_DATA);
        res.setCompressedSize(compressedSize ? in.readLong() : ExtraField.NO_DATA);
        res.setOffsLocalHeaderRelative(offs ? in.readLong() : ExtraField.NO_DATA);
        res.setDiskNumber(diskNumber ? in.readInt() : ExtraField.NO_DATA);

        return res;
    }

}