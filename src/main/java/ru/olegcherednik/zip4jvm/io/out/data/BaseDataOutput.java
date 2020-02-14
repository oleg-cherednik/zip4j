package ru.olegcherednik.zip4jvm.io.out.data;

import ru.olegcherednik.zip4jvm.io.AbstractMarker;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 03.08.2019
 */
public abstract class BaseDataOutput extends AbstractMarker implements DataOutput {

    private static final int OFFS_BYTE = 0;
    private static final int OFFS_WORD = 1;
    private static final int OFFS_DWORD = 3;
    private static final int OFFS_QWORD = 7;

    private static final ThreadLocal<byte[]> THREAD_LOCAL_BUF = ThreadLocal.withInitial(() -> new byte[15]);

    @Override
    public void writeByte(int val) throws IOException {
        convertAndWrite(val, OFFS_BYTE, 1);
    }

    @Override
    public void writeWord(int val) throws IOException {
        convertAndWrite(val, OFFS_WORD, 2);
    }

    @Override
    public void writeDword(long val) throws IOException {
        convertAndWrite(val, OFFS_DWORD, 4);
    }

    @Override
    public void writeQword(long val) throws IOException {
        convertAndWrite(val, OFFS_QWORD, 8);
    }

    private void convertAndWrite(long val, int offs, int len) throws IOException {
        byte[] buf = THREAD_LOCAL_BUF.get();
        fromLong(val, buf, offs, len);
        write(buf, offs, len);
    }

    @Override
    public void write(byte[] buf, int offs, int len) throws IOException {
        long offsFrom = getOffs();
        writeInternal(buf, offs, len);
        incTic(getOffs() - offsFrom);
    }

    protected abstract void writeInternal(byte[] buf, int offs, int len) throws IOException;

}
