package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 10.03.2019
 */
@RequiredArgsConstructor
public final class CentralDirectoryWriter implements Writer {

    private final CentralDirectory centralDirectory;

    @Override
    public void write(DataOutput out) throws IOException {
        // TODO check that exactly required byte were written
        new FileHeaderWriter(centralDirectory.getFileHeaders()).write(out);
        new DigitalSignatureWriter(centralDirectory.getDigitalSignature()).write(out);
    }

}
