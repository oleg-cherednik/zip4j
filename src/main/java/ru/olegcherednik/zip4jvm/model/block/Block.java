package ru.olegcherednik.zip4jvm.model.block;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.in.data.ZipDataInput;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.utils.function.LocalSupplier;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 19.10.2019
 */
@Getter
@NoArgsConstructor
public class Block {

    public static final Block NULL = new Block();

    private long size;
    @Setter
    private long offs;
    private long disk;
    private String fileName;
    @Setter
    private ZipModel zipModel;

    public <T> T calc(DataInput in, LocalSupplier<T> task) throws IOException {
        try {
            zipModel = in instanceof ZipDataInput ? ((ZipDataInput)in).getZipModel() : null;
            offs = in.getOffs();
            disk = in.getDisk();
            fileName = in.getFileName();
            return task.get();
        } finally {
            calc(in.getOffs());
        }
    }

    public void calc(long offs) {
        size = offs - this.offs;
    }

    public byte[] getData() {
        if (zipModel == null || size > Integer.MAX_VALUE)
            return ArrayUtils.EMPTY_BYTE_ARRAY;

        try (DataInput in = zipModel.createDataInput()) {
            in.skip(offs);
            return in.readBytes((int)size);
        } catch(Exception e) {
            e.printStackTrace();
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
    }

    public void setDisk(long disk, String fileName) {
        this.disk = disk;
        this.fileName = fileName;
    }

    @Override
    public String toString() {
        return String.format("offs: %d, size: %s, disk: %d", offs, size, disk);
    }
}
