package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.GeneralPurposeFlag;
import ru.olegcherednik.zip4jvm.model.LocalFileHeader;
import ru.olegcherednik.zip4jvm.model.Version;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 08.03.2019
 */
@RequiredArgsConstructor
public class LocalFileHeaderReader implements Reader<LocalFileHeader> {

    private final long offs;
    private final Function<Charset, Charset> customizeCharset;

    @Override
    public final LocalFileHeader read(DataInput in) throws IOException {
        findSignature(in);
        return readLocalFileHeader(in);
    }

    protected LocalFileHeader readLocalFileHeader(DataInput in) throws IOException {
        in.skip(in.dwordSignatureSize());

        LocalFileHeader localFileHeader = new LocalFileHeader();

        localFileHeader.setVersionToExtract(Version.of(in.readWord()));
        localFileHeader.setGeneralPurposeFlag(new GeneralPurposeFlag(in.readWord()));
        localFileHeader.setCompressionMethod(CompressionMethod.parseCode(in.readWord()));
        localFileHeader.setLastModifiedTime((int)in.readDword());
        localFileHeader.setCrc32(in.readDword());
        localFileHeader.setCompressedSize(in.readDword());
        localFileHeader.setUncompressedSize(in.readDword());

        int fileNameLength = in.readWord();
        int extraFieldLength = in.readWord();
        Charset charset = localFileHeader.getGeneralPurposeFlag().getCharset();

        localFileHeader.setFileName(in.readString(fileNameLength, customizeCharset.apply(charset)));
        localFileHeader.setExtraField(readExtraFiled(extraFieldLength, localFileHeader, in));

        return localFileHeader;
    }

    protected ExtraField readExtraFiled(int size, LocalFileHeader localFileHeader, DataInput in) throws IOException {
        return new ExtraFieldReader(size, ExtraFieldReader.getReaders(localFileHeader)).read(in);
    }

    private void findSignature(DataInput in) throws IOException {
        in.seek(offs);

        if (in.readDwordSignature() != LocalFileHeader.SIGNATURE)
            throw new Zip4jvmException("invalid local file header signature");

        in.backward(in.dwordSignatureSize());
    }

}
