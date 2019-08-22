package com.cop.zip4j.io.writers;

import com.cop.zip4j.io.out.DataOutput;
import com.cop.zip4j.model.CentralDirectory;
import com.cop.zip4j.model.EndCentralDirectory;
import com.cop.zip4j.model.ExtraField;
import com.cop.zip4j.model.Zip64;
import com.cop.zip4j.model.ZipModel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

@RequiredArgsConstructor
public final class ZipModelWriter {

    public static final int ZIP64_EXTRA_BUF = 50;
    private static final String MARK = "header";

    @NonNull
    private final ZipModel zipModel;
    private final boolean validate;

    // TODO do we really need validate flag?
    public void finalizeZipFile(@NonNull DataOutput out) throws IOException {
        if (validate)
            processHeaderData(out);

        EndCentralDirectory endCentralDirectory = zipModel.getEndCentralDirectory();
        out.mark(MARK);
        updateFileHeaders();
        new CentralDirectoryWriter(zipModel.getCentralDirectory(), zipModel.getCharset()).write(out);
        endCentralDirectory.setSize(out.getWrittenBytesAmount(MARK));

        zipModel.updateZip64();

        if (zipModel.isZip64() && validate) {
            Zip64.EndCentralDirectoryLocator locator = zipModel.getZip64().getEndCentralDirectoryLocator();
            locator.setStartDisk(out.getCounter());
            locator.setTotalDisks(out.getCounter() + 1);
        }

        new Zip64Writer(zipModel.getZip64()).write(out);
        new EndCentralDirectoryWriter(endCentralDirectory, zipModel.getCharset()).write(out);
    }

    private void processHeaderData(DataOutput out) throws IOException {
        EndCentralDirectory endCentralDirectory = zipModel.getEndCentralDirectory();
        // TODO duplication set; see previous step
        endCentralDirectory.setOffs(out.getOffs());

        if (zipModel.isZip64()) {
            Zip64.EndCentralDirectoryLocator locator = zipModel.getZip64().getEndCentralDirectoryLocator();
            locator.setStartDisk(out.getCounter());
            locator.setTotalDisks(out.getCounter() + 1);
        }

        endCentralDirectory.setSplitParts(out.getCounter());
        endCentralDirectory.setStartDiskNumber(out.getCounter());
    }

    @Deprecated
    private void updateFileHeaders() {
        zipModel.getCentralDirectory().getFileHeaders().forEach(this::updateZip64);
    }

    // TODO should be updated on the fly
    @Deprecated
    private void updateZip64(CentralDirectory.FileHeader fileHeader) {
        if (fileHeader.isWriteZip64FileSize() || fileHeader.isWriteZip64OffsetLocalHeader())
            zipModel.zip64();

//        if (fileHeader.getExtraField() == ExtraField.NULL)
//            fileHeader.setExtraField(new ExtraField());
//        if (fileHeader.getExtraField().getZip64ExtendedInfo() == )
//            fileHeader.getExtraField().setZip64ExtendedInfo(new Zip64ExtendedInfo());

        // TODO move it before
        Zip64.ExtendedInfo info = fileHeader.getExtraField().getExtendedInfo();

        if (info != Zip64.ExtendedInfo.NULL) {
            int size = info.getLength() - Zip64.ExtendedInfo.SIZE_FIELD;
            info = Zip64.ExtendedInfo.builder()
                                     .size(size)
                                     .uncompressedSize(fileHeader.isWriteZip64FileSize() ? fileHeader.getUncompressedSize() : ExtraField.NO_DATA)
                                     .compressedSize(fileHeader.isWriteZip64FileSize() ? fileHeader.getCompressedSize() : ExtraField.NO_DATA)
                                     .offsLocalHeaderRelative(
                                             fileHeader.isWriteZip64OffsetLocalHeader() ? fileHeader.getOffsLocalFileHeader() : ExtraField.NO_DATA)
                                     .build();

            fileHeader.getExtraField().setExtendedInfo(info);
        }
    }

}
