package ru.olegcherednik.zip4jvm.io.readers;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.model.DataDescriptor;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 25.07.2019
 */
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class DataDescriptorReader implements Reader<DataDescriptor> {

    public static DataDescriptorReader get(boolean zip64) {
        return zip64 ? new Zip64() : new Standard();
    }

    public static class Standard extends DataDescriptorReader {

        @Override
        public DataDescriptor read(DataInput in) throws IOException {
            long offs = in.getOffs();

            if (in.readDwordSignature() != DataDescriptor.SIGNATURE)
                throw new Zip4jvmException("DataDescriptor signature expected at offs=" + offs);

            long crc32 = in.readDword();
            long compressedSize = in.readDword();
            long uncompressedSize = in.readDword();

            return new DataDescriptor(crc32, compressedSize, uncompressedSize);
        }
    }

    public static class Zip64 extends DataDescriptorReader {

        @Override
        public DataDescriptor read(DataInput in) throws IOException {
            long offs = in.getOffs();

            if (in.readDwordSignature() != DataDescriptor.SIGNATURE)
                throw new Zip4jvmException("DataDescriptor signature expected at offs=" + offs);

            long crc32 = in.readDword();
            long compressedSize = in.readQword();
            long uncompressedSize = in.readQword();

            return new DataDescriptor(crc32, compressedSize, uncompressedSize);
        }
    }

}
