package ru.olegcherednik.zip4jvm.view;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.block.Block;

import java.io.PrintStream;
import java.util.Objects;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotNull;

/**
 * @author Oleg Cherednik
 * @since 14.10.2019
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Zip64View {

    public static final class EndCentralDirectoryLocatorView extends BaseView {

        private final Zip64.EndCentralDirectoryLocator locator;
        private final Block block;

        public EndCentralDirectoryLocatorView(Zip64.EndCentralDirectoryLocator locator, Block block, int offs, int columnWidth, long totalDisks) {
            super(offs, columnWidth, totalDisks);
            this.locator = requireNotNull(locator, "Zip64View.locator");
            this.block = requireNotNull(block, "Zip64View.block");
        }

        @Override
        public boolean print(PrintStream out) {
            printTitle(out, Zip64.EndCentralDirectoryLocator.SIGNATURE, "ZIP64 End of Central directory locator", block);
            printLine(out, String.format("part number of new-end-of-central-dir (%04X):", locator.getMainDisk()), locator.getMainDisk() + 1);
            printLine(out, "relative offset of new-end-of-central-dir:", String.format("%1$d (0x%1$08X) bytes", locator.getOffs()));
            printLine(out, "total number of parts in archive:", locator.getTotalDisks());
            return true;
        }

    }

    public static final class EndCentralDirectoryView extends BaseView {

        private final Zip64.EndCentralDirectory dir;
        private final Block block;

        public EndCentralDirectoryView(Zip64.EndCentralDirectory dir, Block block, int offs, int columnWidth, long totalDisks) {
            super(offs, columnWidth, totalDisks);
            this.dir = dir;
            this.block = block;

            Objects.requireNonNull(dir, "'endCentralDirectory' must not be null");
            Objects.requireNonNull(block, "'block' must not be null");
        }

        @Override
        public boolean print(PrintStream out) {
            printTitle(out, Zip64.EndCentralDirectory.SIGNATURE, "ZIP64 End of Central directory record", block);
            printLine(out, "number of bytes in rest of record:", String.format("%d bytes", dir.getEndCentralDirectorySize()));
            printVersion(out);
            printLine(out, String.format("part number of this part (%04d):", dir.getTotalDisks()), dir.getTotalDisks() + 1);
            printLine(out, String.format("part number of start of central dir (%04d):", dir.getMainDisk()), dir.getMainDisk() + 1);
            printLine(out, "number of entries in central dir in this part:", dir.getDiskEntries());
            printLine(out, "total number of entries in central dir:", dir.getTotalEntries());
            printLine(out, "size of central dir:", String.format("%1$d (0x%1$08X) bytes", dir.getCentralDirectorySize()));
            printLine(out, "relative offset of central dir:", String.format("%1$d (0x%1$08X) bytes", dir.getCentralDirectoryOffs()));
            printExtensibleDataSector(out);
            return true;
        }

        private void printVersion(PrintStream out) {
            new VersionView(dir.getVersionMadeBy(), dir.getVersionToExtract(), offs, columnWidth).print(out);
        }

        private void printExtensibleDataSector(PrintStream out) {
//            printLine(out, "extensible data sector:", String.format("%d bytes", dir.getExtensibleDataSector().length));
//            new ByteArrayHexView(dir.getExtensibleDataSector(), offs, columnWidth).print(out);
        }
    }

}
