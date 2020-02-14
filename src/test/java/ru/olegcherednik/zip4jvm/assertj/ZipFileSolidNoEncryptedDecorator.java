package ru.olegcherednik.zip4jvm.assertj;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.archivers.zip.ZipMethod;
import org.apache.commons.io.IOUtils;
import org.tukaani.xz.LZMAInputStream;
import ru.olegcherednik.zip4jvm.ZipInfo;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.zip.ZipEntry;

/**
 * @author Oleg Cherednik
 * @since 03.10.2019
 */
@SuppressWarnings("MagicConstant")
class ZipFileSolidNoEncryptedDecorator extends ZipFileDecorator {

    public ZipFileSolidNoEncryptedDecorator(Path zip) {
        super(zip);
    }

    @Override
    public InputStream getInputStream(ZipEntry entry) {
        try {
            return new InputStream() {
                private final ZipFile zipFile = new ZipFile(zip.toFile());
                private final InputStream delegate;

                {
                    ZipArchiveEntry zipEntry = zipFile.getEntry(entry.getName());

                    if (zipFile.canReadEntryData(zipEntry))
                        delegate = zipFile.getInputStream(zipEntry);
                    else if (zipEntry.getMethod() == ZipMethod.LZMA.getCode()) {
                        InputStream in = zipFile.getRawInputStream(zipEntry);
                        ByteBuffer buffer = ByteBuffer.wrap(IOUtils.readFully(in, 9)).order(ByteOrder.LITTLE_ENDIAN);

                        int majorVersion = buffer.get();
                        int minorVersion = buffer.get();
                        int size = buffer.getShort() & 0xFFFF;

                        if (size != 5)
                            throw new UnsupportedOperationException("ZipEntry LZMA should have size 5 in header: " + zipEntry.getName());

                        CentralDirectory.FileHeader fileHeader = ZipInfo.zip(zip).getFileHeader(zipEntry.getName());
                        boolean lzmaEosMarker = fileHeader.getGeneralPurposeFlag().isLzmaEosMarker();
                        long uncompSize = lzmaEosMarker ? -1 : fileHeader.getUncompressedSize();
                        byte propByte = buffer.get();
                        int dictSize = buffer.getInt();
                        delegate = new LZMAInputStream(in, uncompSize, propByte, dictSize);
                    } else
                        throw new UnsupportedOperationException("ZipEntry data can't be read: " + zipEntry.getName());
                }

                @Override
                public int read() throws IOException {
                    return delegate.read();
                }

                @Override
                public void close() throws IOException {
                    delegate.close();
                    zipFile.close();
                }
            };
        } catch(Zip4jvmException e) {
            throw e;
        } catch(Exception e) {
            throw new Zip4jvmException(e);
        }
    }

}
