package ru.olegcherednik.zip4jvm.crypto.strong;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Decoder;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 09.10.2019
 */
@RequiredArgsConstructor
public final class StrongDecoder implements Decoder {

    public static StrongDecoder create(ZipEntry zipEntry, DataInput in) throws IOException {
        try {
            // read header
            int ivSize = in.readWord();
            byte[] iv = in.readBytes(ivSize);
            long size = in.readDword();
            int format = in.readWord();
            String encAlgId = in.readString(2, Charsets.UTF_8);
            int key = in.readWord();
            /*
            	case 0x0001: // Password is required to decrypt.
            case 0x0002: // Certificates only.
            case 0x0003: //Password or certificate required to decrypt.
             */
            int flags = in.readWord();
            int rndSize = in.readWord();
            byte[] encData = in.readBytes(rndSize);
            long reserverd = in.readDword();
            int pswSize = in.readWord();
            byte[] psw = in.readBytes(pswSize);
            long crc32 = in.readDword();

//        PkwareEngine engine = new PkwareEngine(zipEntry.getPassword());
//        PkwareHeader.read(engine, zipEntry, in);
            return new StrongDecoder(/*engine*/);
        } catch(
                Zip4jvmException e) {
            throw e;
        } catch(Exception e) {
            throw new Zip4jvmException(e);
        }
    }

    @Override
    public void decrypt(byte[] buf, int offs, int len) {

    }

    @Override
    public long getCompressedSize(ZipEntry zipEntry) {
        return 0;
    }
}
