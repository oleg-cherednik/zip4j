package ru.olegcherednik.zip4jvm.model.builders;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import ru.olegcherednik.zip4jvm.model.Version;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.ZipModel;

/**
 * @author Oleg Cherednik
 * @since 31.08.2019
 */
@RequiredArgsConstructor
public final class Zip64Builder {

    private final ZipModel zipModel;
    private final long disk;

    public Zip64 build() {
        return zipModel.isZip64() ? Zip64.of(createLocator(), createEndCentralDirectory()) : Zip64.NULL;
    }

    private Zip64.EndCentralDirectoryLocator createLocator() {
        Zip64.EndCentralDirectoryLocator locator = new Zip64.EndCentralDirectoryLocator();
        locator.setOffs(zipModel.getCentralDirectoryOffs() + zipModel.getCentralDirectorySize());
        locator.setMainDisk(disk);
        locator.setTotalDisks(disk);
        return locator;
    }

    private Zip64.EndCentralDirectory createEndCentralDirectory() {
        byte[] extensibleDataSector = getExtensibleDataSector();
        /* see 4.3.14.1 */
        long size = Zip64.EndCentralDirectory.SIZE + extensibleDataSector.length;

        Zip64.EndCentralDirectory endCentralDirectory = new Zip64.EndCentralDirectory();
        endCentralDirectory.setEndCentralDirectorySize(size);
        endCentralDirectory.setVersionMadeBy(Version.of(Version.FileSystem.MS_DOS_OS2_NT_FAT, 20));
        endCentralDirectory.setVersionToExtract(Version.of(Version.FileSystem.MS_DOS_OS2_NT_FAT, 20));
        endCentralDirectory.setTotalDisks(zipModel.getTotalDisks());
        endCentralDirectory.setMainDisk(zipModel.getMainDisk());
        endCentralDirectory.setDiskEntries(countNumberOfFileHeaderEntriesOnDisk());
        endCentralDirectory.setTotalEntries(zipModel.getTotalEntries());
        endCentralDirectory.setCentralDirectorySize(zipModel.getCentralDirectorySize());
        endCentralDirectory.setCentralDirectoryOffs(zipModel.getCentralDirectoryOffs());
//        endCentralDirectory.setExtensibleDataSector(extensibleDataSector);
        return endCentralDirectory;
    }

    private int countNumberOfFileHeaderEntriesOnDisk() {
        if (zipModel.isSplit())
            return (int)zipModel.getZipEntries().stream()
                                .filter(zipEntry -> zipEntry.getDisk() == zipModel.getTotalDisks())
                                .count();

        return zipModel.getTotalEntries();
    }

    /** see 4.4.27 */
    private static byte[] getExtensibleDataSector() {
        return ArrayUtils.EMPTY_BYTE_ARRAY;
    }

}
