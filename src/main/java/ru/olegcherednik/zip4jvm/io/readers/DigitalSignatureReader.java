package ru.olegcherednik.zip4jvm.io.readers;

import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 13.04.2019
 */
public class DigitalSignatureReader implements Reader<CentralDirectory.DigitalSignature> {

    @Override
    public final CentralDirectory.DigitalSignature read(DataInput in) throws IOException {
        return findSignature(in) ? readDigitalSignature(in) : null;
    }

    protected CentralDirectory.DigitalSignature readDigitalSignature(DataInput in) throws IOException {
        in.skip(in.dwordSignatureSize());

        CentralDirectory.DigitalSignature digitalSignature = new CentralDirectory.DigitalSignature();
        digitalSignature.setSignatureData(in.readBytes(in.readWord()));

        return digitalSignature;
    }

    private static boolean findSignature(DataInput in) throws IOException {
        boolean exists = in.readDwordSignature() == CentralDirectory.DigitalSignature.SIGNATURE;
        in.backward(exists ? in.dwordSignatureSize() : 0);
        return exists;
    }
}
