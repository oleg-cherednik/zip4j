package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.io.in.SingleZipInputStream;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.EndCentralDirectory;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.builders.ZipModelBuilder;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * Start reading from the end of the file.
 *
 * <pre>
 * ...
 * [zip64 end of central directory record]
 * [zip64 end of central directory locator]
 * [end of central directory record]
 * EOF
 * </pre>
 *
 * @author Oleg Cherednik
 * @since 06.03.2019
 */
@RequiredArgsConstructor
public final class ZipModelReader {

    private final Path zip;
    private final Function<Charset, Charset> charsetCustomizer;

    public ZipModel read() throws IOException {
        try (DataInput in = new SingleZipInputStream(zip)) {
            EndCentralDirectory endCentralDirectory = new EndCentralDirectoryReader(charsetCustomizer).read(in);
            Zip64 zip64 = new Zip64Reader().read(in);

            long offs = ZipModelBuilder.getCentralDirectoryOffs(endCentralDirectory, zip64);
            long totalEntries = ZipModelBuilder.getTotalEntries(endCentralDirectory, zip64);
            CentralDirectory centralDirectory = getCentralDirectoryReader(zip64, offs, totalEntries).read(in);

            return new ZipModelBuilder(zip, endCentralDirectory, zip64, centralDirectory, charsetCustomizer).build();
        }
    }

    private Reader<CentralDirectory> getCentralDirectoryReader(Zip64 zip64, long offs, long totalEntries) {
        if(zip64 == Zip64.NULL)
            return new CentralDirectoryReader(offs, totalEntries, charsetCustomizer);

        Zip64.ExtensibleDataSector extensibleDataSector = zip64.getEndCentralDirectory().getExtensibleDataSector();

        if (extensibleDataSector == Zip64.ExtensibleDataSector.NULL)
            return new CentralDirectoryReader(offs, totalEntries, charsetCustomizer);
        return new SecureCentralDirectoryReader(offs, totalEntries, charsetCustomizer, extensibleDataSector);
    }

}
