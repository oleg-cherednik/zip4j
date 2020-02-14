package ru.olegcherednik.zip4jvm;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * @author Oleg Cherednik
 * @since 20.09.2019
 */
@SuppressWarnings("FieldNamingConvention")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TestData {

        public static final Path dirRoot = createTempDirectory("zip4jvm");
//    public static final Path dirRoot = Paths.get("d:/zip4jvm/foo");
    public static final Path dirSrc = dirRoot.resolve("src");

    public static final String dirNameBikes = "bikes";
    public static final String dirNameCars = "cars";
    public static final String dirNameEmpty = "empty_dir";

    public static final String zipDirNameBikes = dirNameBikes + '/';
    public static final String zipDirNameCars = dirNameCars + '/';
    public static final String zipDirNameEmpty = dirNameEmpty + '/';

    public static final String fileNameDucati = "ducati-panigale-1199.jpg";
    public static final String fileNameHonda = "honda-cbr600rr.jpg";
    public static final String fileNameKawasaki = "kawasaki-ninja-300.jpg";
    public static final String fileNameSuzuki = "suzuki-gsxr750.jpg";

    public static final String fileNameBentley = "bentley-continental.jpg";
    public static final String fileNameFerrari = "ferrari-458-italia.jpg";
    public static final String fileNameWiesmann = "wiesmann-gt-mf5.jpg";

    public static final String fileNameEmpty = "empty_file.txt";
    public static final String fileNameMcdonnelDouglas = "mcdonnell-douglas-f15-eagle.jpg";
    public static final String fileNameOlegCherednik = "Oleg Cherednik.txt";
    public static final String fileNameSaintPetersburg = "saint-petersburg.jpg";
    public static final String fileNameSigSauer = "sig-sauer-pistol.jpg";

    public static final Path dirBikes = dirSrc.resolve(dirNameBikes);
    public static final Path dirCars = dirSrc.resolve(dirNameCars);
    public static final Path dirEmpty = dirSrc.resolve(dirNameEmpty);

    public static final Path fileDucati = dirBikes.resolve(fileNameDucati);
    public static final Path fileHonda = dirBikes.resolve(fileNameHonda);
    public static final Path fileKawasaki = dirBikes.resolve(fileNameKawasaki);
    public static final Path fileSuzuki = dirBikes.resolve(fileNameSuzuki);

    public static final Path fileBentley = dirCars.resolve(fileNameBentley);
    public static final Path fileFerrari = dirCars.resolve(fileNameFerrari);
    public static final Path fileWiesmann = dirCars.resolve(fileNameWiesmann);

    public static final Path fileEmpty = dirSrc.resolve(fileNameEmpty);
    public static final Path fileMcdonnelDouglas = dirSrc.resolve(fileNameMcdonnelDouglas);
    public static final Path fileOlegCherednik = dirSrc.resolve(fileNameOlegCherednik);
    public static final Path fileSaintPetersburg = dirSrc.resolve(fileNameSaintPetersburg);
    public static final Path fileSigSauer = dirSrc.resolve(fileNameSigSauer);

    public static final List<Path> filesDirBikes = Arrays.asList(fileDucati, fileHonda, fileKawasaki, fileSuzuki);
    public static final List<Path> filesDirCars = Arrays.asList(fileBentley, fileFerrari, fileWiesmann);
    public static final List<Path> filesDirSrc = Arrays.asList(fileEmpty, fileMcdonnelDouglas, fileOlegCherednik, fileSaintPetersburg,
            fileSigSauer);

    public static final List<Path> contentDirSrc = Arrays.asList(dirBikes, dirCars, dirEmpty, fileEmpty, fileMcdonnelDouglas, fileOlegCherednik,
            fileSaintPetersburg, fileSigSauer);

    // store
    public static final Path zipStoreSolid = dirRoot.resolve("store/solid/off/src.zip");
    public static final Path zipStoreSolidPkware = dirRoot.resolve("store/solid/pkware/src.zip");
    public static final Path zipStoreSolidAes = dirRoot.resolve("store/solid/aes/src.zip");
    public static final Path zipStoreSplit = dirRoot.resolve("store/split/off/src.zip");
    public static final Path zipStoreSplitPkware = dirRoot.resolve("store/split/pkware/src.zip");
    public static final Path zipStoreSplitAes = dirRoot.resolve("store/split/aes/src.zip");

    // deflate
    public static final Path zipDeflateSolid = dirRoot.resolve("deflate/solid/off/src.zip");
    public static final Path zipDeflateSplit = dirRoot.resolve("deflate/split/off/src.zip");
    public static final Path zipDeflateSolidPkware = dirRoot.resolve("deflate/solid/pkware/src.zip");
    public static final Path zipDeflateSolidAes = dirRoot.resolve("deflate/solid/aes/src.zip");

    // winrar
    public static final Path winRarStoreSolidZip = Paths.get("src/test/resources/winrar/store_solid_off.zip").toAbsolutePath();
    public static final Path winRarStoreSolidPkwareZip = Paths.get("src/test/resources/winrar/store_solid_pkware.zip").toAbsolutePath();
    public static final Path winRarStoreSolidAesZip = Paths.get("src/test/resources/winrar/store_solid_aes.zip").toAbsolutePath();
    public static final Path winRarDeflateSolidZip = Paths.get("src/test/resources/winrar/deflate_solid_off.zip").toAbsolutePath();
    public static final Path winRarDeflateSolidPkwareZip = Paths.get("src/test/resources/winrar/deflate_solid_pkware.zip").toAbsolutePath();
    public static final Path winRarDeflateSolidAesZip = Paths.get("src/test/resources/winrar/deflate_solid_aes.zip").toAbsolutePath();

    // 7-Zip
    public static final Path sevenZipStoreSplitZip = Paths.get("src/test/resources/seven-zip/store_split_off/src.zip.001").toAbsolutePath();
    public static final Path sevenZipLzmaSolidZip = Paths.get("src/test/resources/seven-zip/lzma_solid_off.zip").toAbsolutePath();
    public static final Path sevenZipLzmaSolidAesZip = Paths.get("src/test/resources/seven-zip/lzma_solid_aes.zip").toAbsolutePath();

    private static Path createTempDirectory(String prefix) {
        try {
            return Files.createTempDirectory(prefix);
        } catch(IOException e) {
            throw new Zip4jvmException(e);
        }
    }

}
