package ru.olegcherednik.zip4jvm.view.extrafield;

import ru.olegcherednik.zip4jvm.model.ExtraField;
import ru.olegcherednik.zip4jvm.model.Zip64;

/**
 * @author Oleg Cherednik
 * @since 26.10.2019
 */
final class Zip64ExtendedInfoView extends ExtraFieldRecordView<Zip64.ExtendedInfo> {

    public static BaseBuilder<Zip64.ExtendedInfo, Zip64ExtendedInfoView> builder() {
        return new BaseBuilder<>(Zip64ExtendedInfoView::new);
    }

    private Zip64ExtendedInfoView(BaseBuilder<Zip64.ExtendedInfo, Zip64ExtendedInfoView> builder) {
        super(builder, (record, view, out) -> {
            if (record.getUncompressedSize() != ExtraField.NO_DATA)
                view.printLine(out, "  original compressed size:", String.format("%d bytes", record.getUncompressedSize()));
            if (record.getCompressedSize() != ExtraField.NO_DATA)
                view.printLine(out, "  original uncompressed size:", String.format("%d bytes", record.getCompressedSize()));
            if (record.getLocalFileHeaderOffs() != ExtraField.NO_DATA)
                view.printLine(out, "  original relative offset of local header:",
                        String.format("%1$d (0x%1$08X) bytes", record.getLocalFileHeaderOffs()));
            if (record.getDisk() != ExtraField.NO_DATA)
                view.printLine(out, String.format("  original part number of this part (%04X):", record.getDisk()), record.getDisk());
        });
    }
}
