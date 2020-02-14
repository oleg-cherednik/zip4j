package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 13.04.2019
 */
@RequiredArgsConstructor
final class DigitalSignatureWriter implements Writer {

    private final CentralDirectory.DigitalSignature digitalSignature;

    @Override
    public void write(DataOutput out) throws IOException {
        if (digitalSignature == null)
            return;

        out.writeDwordSignature(CentralDirectory.DigitalSignature.SIGNATURE);
        out.writeWord(ArrayUtils.getLength(digitalSignature.getSignatureData()));
        out.writeBytes(digitalSignature.getSignatureData());
    }

}
