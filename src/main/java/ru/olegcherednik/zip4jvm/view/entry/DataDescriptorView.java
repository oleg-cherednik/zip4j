package ru.olegcherednik.zip4jvm.view.entry;

import ru.olegcherednik.zip4jvm.model.DataDescriptor;
import ru.olegcherednik.zip4jvm.model.block.Block;
import ru.olegcherednik.zip4jvm.view.BaseView;
import ru.olegcherednik.zip4jvm.view.SizeView;

import java.io.PrintStream;
import java.util.Objects;

/**
 * @author Oleg Cherednik
 * @since 26.10.2019
 */
public final class DataDescriptorView extends BaseView {

    private final DataDescriptor dataDescriptor;
    private final Block block;
    private final long pos;

    public DataDescriptorView(DataDescriptor dataDescriptor, Block block, long pos, int offs, int columnWidth, long totalDisks) {
        super(offs, columnWidth, totalDisks);
        this.dataDescriptor = dataDescriptor;
        this.block = block;
        this.pos = pos;

        Objects.requireNonNull(dataDescriptor, "'dataDescriptor' must not be null");
        Objects.requireNonNull(block, "'block' must not be null");
    }

    @Override
    public boolean print(PrintStream out) {
        printSubTitle(out, DataDescriptor.SIGNATURE, pos, "Data descriptor", block);
        printLine(out, "32-bit CRC value:", String.format("0x%08X", dataDescriptor.getCrc32()));
        new SizeView("compressed size:", dataDescriptor.getCompressedSize(), offs, columnWidth).print(out);
        new SizeView("uncompressed size:", dataDescriptor.getUncompressedSize(), offs, columnWidth).print(out);
        return true;
    }

}
