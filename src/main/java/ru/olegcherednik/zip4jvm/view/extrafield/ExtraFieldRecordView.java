package ru.olegcherednik.zip4jvm.view.extrafield;

import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.block.Block;
import ru.olegcherednik.zip4jvm.view.BaseView;

import java.io.PrintStream;

/**
 * @author Oleg Cherednik
 * @since 24.11.2019
 */
public abstract class ExtraFieldRecordView<T extends ExtraField.Record> extends BaseView {

    private final T record;
    private final Block block;
    private final PrintConsumer<T, BaseView> printConsumer;

    protected ExtraFieldRecordView(Builder<T, ?> builder, PrintConsumer<T, BaseView> printConsumer) {
        super(builder.getOffs(), builder.getColumnWidth());
        record = builder.getRecord();
        block = builder.getBlock();
        this.printConsumer = printConsumer;
    }

    protected int getSignature() {
        return record.getSignature();
    }

    protected String getTitle() {
        return record.getTitle();
    }

    public String getFileName() {
        String title = getTitle();
        title = title.replaceAll(" ", "_");
        title = title.replaceAll("[/\\\\]", "-");
        return String.format("(0x%04X)_%s", getSignature(), title);
    }

    @Override
    public boolean print(PrintStream out) {
        if (record == null)
            return false;

        printValueLocation(out, String.format("(0x%04X) %s:", getSignature(), getTitle()), block);
        printConsumer.print(record, this, out);

        return true;
    }

}
