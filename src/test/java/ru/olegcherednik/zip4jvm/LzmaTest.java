package ru.olegcherednik.zip4jvm;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @author Oleg Cherednik
 * @since 01.02.2020
 */
public class LzmaTest {

    public static void main(String... args) throws IOException {
        Path zip = Paths.get("d:/zip4jvm/tmp/lzma/lzma_64kb.zip");
        Path destDir = Paths.get("d:/zip4jvm/tmp/lzma/out");
        UnzipIt.zip(zip).destDir(destDir).extract();
    }

}
