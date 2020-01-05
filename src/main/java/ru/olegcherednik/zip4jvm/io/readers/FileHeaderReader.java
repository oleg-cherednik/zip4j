package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.SignatureWasNotFoundException;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.CompressionMethod;
import ru.olegcherednik.zip4jvm.model.ExternalFileAttributes;
import ru.olegcherednik.zip4jvm.model.InternalFileAttributes;
import ru.olegcherednik.zip4jvm.model.Version;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Function;

import static ru.olegcherednik.zip4jvm.model.ExternalFileAttributes.PROP_OS_NAME;

/**
 * @author Oleg Cherednik
 * @since 26.04.2019
 */
@RequiredArgsConstructor
public class FileHeaderReader implements Reader<List<CentralDirectory.FileHeader>> {

    private final long total;
    private final Function<Charset, Charset> customizeCharset;

    @Override
    public final List<CentralDirectory.FileHeader> read(DataInput in) throws IOException {
        List<CentralDirectory.FileHeader> fileHeaders = new LinkedList<>();

        for (int i = 0; i < total; i++) {
            checkSignature(in);
            fileHeaders.add(readFileHeader(in));
        }

        return fileHeaders;
    }

    private static void checkSignature(DataInput in) throws IOException {
        long offs = in.getOffs();

        if (in.readDwordSignature() != CentralDirectory.FileHeader.SIGNATURE)
            throw new SignatureWasNotFoundException(CentralDirectory.FileHeader.SIGNATURE, "CentralDirectory", offs);

        in.backward(in.dwordSignatureSize());
    }

    protected CentralDirectory.FileHeader readFileHeader(DataInput in) throws IOException {
        in.skip(in.dwordSignatureSize());

        CentralDirectory.FileHeader fileHeader = new CentralDirectory.FileHeader();

        fileHeader.setVersionMadeBy(Version.of(in.readWord()));
        fileHeader.setVersionToExtract(Version.of(in.readWord()));
        fileHeader.setGeneralPurposeFlagData(in.readWord());
        fileHeader.setCompressionMethod(CompressionMethod.parseCode(in.readWord()));
        fileHeader.setLastModifiedTime((int)in.readDword());
        fileHeader.setCrc32(in.readDword());
        fileHeader.setCompressedSize(in.readDword());
        fileHeader.setUncompressedSize(in.readDword());

        int fileNameLength = in.readWord();
        int extraFieldLength = in.readWord();
        int fileCommentLength = in.readWord();
        Charset charset = customizeCharset.apply(fileHeader.getGeneralPurposeFlag().getCharset());

        fileHeader.setDisk(in.readWord());
        fileHeader.setInternalFileAttributes(getInternalFileAttribute(in.readBytes(InternalFileAttributes.SIZE)));
        fileHeader.setExternalFileAttributes(getExternalFileAttribute(in.readBytes(ExternalFileAttributes.SIZE)));
        fileHeader.setLocalFileHeaderOffs(in.readDword());
        fileHeader.setFileName(in.readString(fileNameLength, charset));
        fileHeader.setExtraField(getExtraFiledReader(extraFieldLength, fileHeader).read(in));
        fileHeader.setComment(in.readString(fileCommentLength, charset));

        return fileHeader;
    }

    @SuppressWarnings("MethodCanBeVariableArityMethod")
    private static InternalFileAttributes getInternalFileAttribute(byte[] data) {
        return InternalFileAttributes.build(data);
    }

    @SuppressWarnings("MethodCanBeVariableArityMethod")
    private static ExternalFileAttributes getExternalFileAttribute(byte[] data) throws IOException {
        return ExternalFileAttributes.build(PROP_OS_NAME).readFrom(data);
    }

    protected ExtraFieldReader getExtraFiledReader(int size, CentralDirectory.FileHeader fileHeader) {
        return new ExtraFieldReader(size, ExtraFieldReader.getReaders(fileHeader));
    }

}
