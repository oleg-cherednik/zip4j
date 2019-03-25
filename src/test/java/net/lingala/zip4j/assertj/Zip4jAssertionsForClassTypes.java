package net.lingala.zip4j.assertj;

import lombok.experimental.UtilityClass;
import org.assertj.core.api.AssertionsForClassTypes;

import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * @author Oleg Cherednik
 * @since 25.03.2019
 */
@UtilityClass
@SuppressWarnings("ExtendsUtilityClass")
public class Zip4jAssertionsForClassTypes extends AssertionsForClassTypes {

    public static AbstractZipFileAssert<?> assertThat(ZipFile actual) {
        return new ZipFileAssert(actual);
    }

    public static AbstractZipEntryAssert<?> assertThat(ZipEntry actual, ZipFile zipFile) {
        return actual.isDirectory() ? new ZipEntryFileAssert(actual, zipFile) : new ZipEntryDirectoryAssert(actual, zipFile);
    }
}
