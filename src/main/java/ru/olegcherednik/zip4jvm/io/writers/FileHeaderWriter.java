package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;

/**
 * @author Oleg Cherednik
 * @since 26.04.2019
 */
@RequiredArgsConstructor
final class FileHeaderWriter implements Writer {

    private final List<CentralDirectory.FileHeader> fileHeaders;

    @Override
    public void write(DataOutput out) throws IOException {
        for (CentralDirectory.FileHeader fileHeader : fileHeaders)
            writeFileHeader(fileHeader, out);
    }

    private static void writeFileHeader(CentralDirectory.FileHeader fileHeader, DataOutput out) throws IOException {
        Charset charset = fileHeader.getGeneralPurposeFlag().getCharset();
        byte[] fileName = fileHeader.getFileName(charset);
        byte[] fileComment = fileHeader.getComment(charset);

        out.writeDwordSignature(CentralDirectory.FileHeader.SIGNATURE);
        out.writeWord(fileHeader.getVersionMadeBy().getData());
        out.writeWord(fileHeader.getVersionToExtract().getData());
        out.writeWord(fileHeader.getGeneralPurposeFlag().getAsInt(fileHeader.getOriginalCompressionMethod()));
        out.writeWord(fileHeader.getCompressionMethod().getCode());
        out.writeDword(fileHeader.getLastModifiedTime());
        out.writeDword(fileHeader.getCrc32());
        out.writeDword(fileHeader.getCompressedSize());
        out.writeDword(fileHeader.getUncompressedSize());
        out.writeWord(fileName.length);
        out.writeWord(fileHeader.getExtraField().getSize());
        out.writeWord(fileComment.length);
        out.writeWord(fileHeader.getDisk());
        out.writeBytes(fileHeader.getInternalFileAttributes().getData());
        out.writeBytes(fileHeader.getExternalFileAttributes().getData());
        out.writeDword(fileHeader.getLocalFileHeaderOffs());
        out.writeBytes(fileName);
        new ExtraFieldWriter(fileHeader.getExtraField()).write(out);
        out.writeBytes(fileComment);
    }
}
