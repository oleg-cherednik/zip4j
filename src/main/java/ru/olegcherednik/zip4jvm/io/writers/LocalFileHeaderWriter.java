package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;
import java.nio.charset.Charset;

/**
 * @author Oleg Cherednik
 * @since 10.03.2019
 */
@RequiredArgsConstructor
public final class LocalFileHeaderWriter implements Writer {

    private final LocalFileHeader localFileHeader;

    @Override
    public void write(DataOutput out) throws IOException {
        Charset charset = localFileHeader.getGeneralPurposeFlag().getCharset();
        byte[] fileName = localFileHeader.getFileName(charset);

        out.writeDwordSignature(LocalFileHeader.SIGNATURE);
        out.writeWord(localFileHeader.getVersionToExtract().getData());
        out.writeWord(localFileHeader.getGeneralPurposeFlag().getAsInt(localFileHeader.getOriginalCompressionMethod()));
        out.writeWord(localFileHeader.getCompressionMethod().getCode());
        out.writeDword(localFileHeader.getLastModifiedTime());
        out.writeDword(localFileHeader.getCrc32());
        out.writeDword(localFileHeader.getCompressedSize());
        out.writeDword(localFileHeader.getUncompressedSize());
        out.writeWord(fileName.length);
        out.writeWord(localFileHeader.getExtraField().getSize());
        out.writeBytes(fileName);

        new ExtraFieldWriter(localFileHeader.getExtraField()).write(out);
    }

}
