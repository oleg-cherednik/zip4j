package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 05.03.2019
 */
@RequiredArgsConstructor
public class CentralDirectoryReader implements Reader<CentralDirectory> {

    protected final long totalEntries;
    protected final Function<Charset, Charset> customizeCharset;

    @Override
    public CentralDirectory read(DataInput in) throws IOException {
        CentralDirectory centralDirectory = new CentralDirectory();
        centralDirectory.setFileHeaders(getFileHeaderReader().read(in));
        centralDirectory.setDigitalSignature(getDigitalSignatureReader().read(in));
        return centralDirectory;
    }

    protected FileHeaderReader getFileHeaderReader() {
        return new FileHeaderReader(totalEntries, customizeCharset);
    }

    protected DigitalSignatureReader getDigitalSignatureReader() {
        return new DigitalSignatureReader();
    }
}
