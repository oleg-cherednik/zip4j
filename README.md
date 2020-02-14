[![Maven Central](https://maven-badges.herokuapp.com/maven-central/ru.oleg-cherednik.zip4jvm/zip4jvm/badge.svg)](https://maven-badges.herokuapp.com/maven-central/ru.oleg-cherednik.zip4jvm/zip4jvm)
[![Build Status](https://travis-ci.org/oleg-cherednik/zip4jvm.svg?branch=master)](https://travis-ci.org/oleg-cherednik/zip4jvm)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.txt)
[![codecov](https://codecov.io/gh/oleg-cherednik/zip4jvm/branch/master/graph/badge.svg)](https://codecov.io/gh/oleg-cherednik/zip4jvm)
[![Known Vulnerabilities](https://snyk.io//test/github/oleg-cherednik/zip4jvm/badge.svg?targetFile=build.gradle)](https://snyk.io//test/github/oleg-cherednik/zip4jvm?targetFile=build.gradle)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/7b6b963fef254ff4b00b8be0304e829b)](https://www.codacy.com/app/oleg-cherednik/zip4jvm?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=oleg-cherednik/zip4jvm&amp;utm_campaign=Badge_Grade)
[![coverity](https://scan.coverity.com/projects/4735/badge.svg)](https://scan.coverity.com/projects/oleg-cherednik-zip4jvm)

<p align="center"><img src="zip.png"><img src="java.png"></p>

zip4jvm - a java library for working with zip files
=====================

## Features

* Add regular files or directories to new or existed zip archive;
* Extract regular files or directories from zip archive;
* Encryption algorithms support:
  * [PKWare](https://en.wikipedia.org/wiki/PKWare)
  * [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* Compression support:
  * Store
  * [DEFLATE](https://en.wikipedia.org/wiki/DEFLATE)
  * [LZMA](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm)
* Individual settings for each zip entry (i.e. some of files can be encrypted, and some - not);
* Streaming support for adding and extracting;
* Read/Write password protected Zip files and streams;
* [ZIP64](https://en.wikipedia.org/wiki/Zip_(file_format)#ZIP64) format support;
* Multi-volume zip archive support:
  * standard, i.e. `filename.zip`, `filename.z01`, `filename.z02`
  * [7-Zip](https://en.wikipedia.org/wiki/7-Zip#Features), i.e. `filename.zip.001`, `filename.zip.002`, `filename.zip.003` (read-only)
* Unicode for comments and file names.

## Gradle

~~~~
compile 'ru.oleg-cherednik.zip4jvm:zip4jvm:1.2'
~~~~

## Maven

~~~~
<dependency>
    <groupId>ru.oleg-cherednik.zip4jvm</groupId>
    <artifactId>zip4jvm</artifactId>
    <version>1.2</version>
</dependency>
~~~~

## Usage

To simplify usage of _zip4jvm_, there're following classes:
* [ZipIt](#zipit) - add files to archive;
* [UnzipIt](#unzipit) - extract files from archive;
* [ZipMisc](#zipmisc) - other zip file activities.
* [ZipInfo](#zipinfo) - zip file information and diagnostics.

### ZipIt

#### Regular files and directories can be represented as `Path`

##### Create (or open existed) zip archive and add regular file */cars/bentley-continental.jpg*

```
Path zip = Paths.get("filename.zip");
Path file = Path.get("/cars/bentley-continental.jpg")
ZipIt.zip(zip).add(file);
```
>```
>/-
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |    |-- honda-cbr600rr.jpg
> |-- saint-petersburg.jpg
>```
>```
>filename.zip
> |-- bentley-continental.jpg
>```

**Note:** regular file is added to the root of the zip archive.

##### Create (or open existed) zip archive and add directory */cars*

```
Path zip = Paths.get("filename.zip");
Path dir = Path.get("/cars")
ZipIt.zip(zip).add(dir);
```
>```
>/-
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |    |-- honda-cbr600rr.jpg
> |-- saint-petersburg.jpg
>```
>```
>filename.zip
> |-- cars
>      |-- bentley-continental.jpg
>      |-- ferrari-458-italia.jpg
>      |-- wiesmann-gt-mf5.jpg
>```

**Note:** directory is added to the root of the zip archive keeping the initial structure.

##### Create (or open existed) zip archive and add some regular files and/or directories

```
Path zip = Paths.get("filename.zip");
Collection<Path> paths = Arrays.asList(
        Paths.get("/bikes/ducati-panigale-1199.jpg"),
        Paths.get("/bikes/honda-cbr600rr.jpg"),
        Paths.get("/cars"),
        Paths.get("/saint-petersburg.jpg"));
ZipIt.zip(zip).add(paths);
```
>```
>/-
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |    |-- honda-cbr600rr.jpg
> |-- saint-petersburg.jpg
>```
>```
>filename.zip
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- ducati-panigale-1199.jpg
> |-- honda-cbr600rr.jpg
> |-- saint-petersburg.jpg
>```

**Note:** each regular file from the list is added to the root of the zip archive.

**Note:** each directory from the list is added to the root of the zip archive keeping the initial structure.

#### Regular files and empty directories are available as `InputStream`

##### Create (or open existed) zip archive and add input streams content as regular files

```
Path zip = Zip4jvmSuite.subDirNameAsMethodName(rootDir).resolve("filename.zip");

try (ZipFile.Writer zipFile = ZipIt.zip(zip).open()) {
    zipFile.add(ZipFile.Entry.builder()
                             .inputStreamSupplier(() -> new FileInputStream("/cars/bentley-continental.jpg"))
                             .fileName("my_cars/bentley-continental.jpg")
                             .uncompressedSize(Files.size(Paths.get("/cars/bentley-continental.jpg"))).build());

    zipFile.add(ZipFile.Entry.builder()
                             .inputStreamSupplier(() -> new FileInputStream("/bikes/kawasaki-ninja-300.jpg"))
                             .fileName("my_bikes/kawasaki.jpg")
                             .uncompressedSize(Files.size(Paths.get("/bikes/kawasaki-ninja-300.jpg"))).build());
}
```
>```
>/-
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |    |-- honda-cbr600rr.jpg
> |-- saint-petersburg.jpg
>```
>```
>filename.zip
> |-- my_cars
> |    |-- bentley-continental.jpg
> |-- my_bikes
> |    |-- kawasaki.jpg
>```

**Note:** each entry is treated as separate input stream of the regular file.

### UnzipIt

### Regular files and directories to `Path` destination

##### Extract all entries into given directory

```
Path zip = Paths.get("filename.zip");
Path destDir = Paths.get("/filename_content");
UnzipIt.zip(zip).destDir(destDir).extract();
```
>```
>filename.zip
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |-- saint-petersburg.jpg
>```
>```
>/filename_content
>  |-- cars
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- bikes
>  |    |-- ducati-panigale-1199.jpg
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg
>```

**Note:** all entries (i.e. regular files and empty directories) are added to the destination
 directory keeping the initial structure.

##### Extract regular file's entry into given directory

```
Path zip = Paths.get("filename.zip");
Path destDir = Paths.get("/filename_content");
UnzipIt.zip(zip).destDir(destDir).extract("/cars/bentley-continental.jpg");
```
>```
>filename.zip
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |-- saint-petersburg.jpg
>```
>```
>/filename_content
>  |-- bentley-continental.jpg
>```

**Note:** regular file's entry is added to the root of the destination directory.

##### Extract directory entries into given directory
```
Path zip = Paths.get("filename.zip");
Path destDir = Paths.get("/filename_content");
UnzipIt.zip(zip).destDir(destDir).extract("cars");
```
>```
>filename.zip
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |-- saint-petersburg.jpg
>```
>```
>/filename_content
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>```

**Note:** extract all entries belong to the given directory; content of these entries is added to
the destination directory keeping the initial structure.

##### Extract some entries into given directory

```
Path zip = Paths.get("filename.zip");
Path destDir = Paths.get("/filename_content");
Collection<Path> fileNames = Arrays.asList("cars", "bikes/ducati-panigale-1199.jpg", "saint-petersburg.jpg");
UnzipIt.zip(zip).destDir(destDir).extract(fileNames);
```
>```
>filename.zip
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |-- saint-petersburg.jpg
>```
>```
>/filename_content
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- ducati-panigale-1199.jpg
>  |-- saint-petersburg.jpg
>```

**Note:** directory is extracting keeping the initial structure; regular file is extracted into root of
destination directory

### Regular files as `InputStream` source

##### Get input stream for regular file's entry

```
Path zip = Paths.get("filename.zip");
Path destFile = Paths.get("/filename_content/bentley.jpg");
try (InputStream in = UnzipIt.zip(zip).stream("/cars/bentley-continental.jpg");
     OutputStream out = new FileOutputStream(destFile.toFile())) {
    IOUtils.copyLarge(in, out);
}
```
>```
>filename.zip
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |-- saint-petersburg.jpg
>```
>```
>/filename_content
>  |-- bentley-continental.jpg
>```

**Note:** Input stream for regular file's entry should be correctly closed to flush all data

### Use password to unzip

For all unzip operation _password provider_ could be optionally set. It could be either single password or
password provider with _fileName_ of the entry as a key.

#### Unzip with single password for entries

```
char[] password = "1".toCharArray();
Path destDir = Paths.get("/filename_content");
List<String> fileNames = Arrays.asList("cars", "bikes/ducati-panigale-1199.jpg", "saint-petersburg.jpg");
UnzipIt.zip(zip).destDir(destDir).password(password).extract(fileNames);
```
>```
>filename.zip  --> password: 1
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |-- saint-petersburg.jpg
>```
>```
>/filename_content
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- ducati-panigale-1199.jpg
>  |-- saint-petersburg.jpg
>```

Or separate password for each entry. The key is the _fileName_ of the entry:

#### Unzip with separate password for each entry

```
Path zip = Paths.get("filename.zip");
Path destFile = Paths.get("filename_content/bentley.jpg");

Function<String, char[]> passwordProvider = fileName -> {
    if (fileName.startsWith("cars/"))
        return "1".toCharArray();
    if (fileName.startsWith("bikes/ducati-panigale-1199.jpg"))
        return "2".toCharArray();
    if (fileName.startsWith("saint-petersburg.jpg"))
            return "3".toCharArray();
    return null;
};

UnzipSettings settings = UnzipSettings.builder().password(passwordProvider).build();
List<Path> fileNames = Arrays.asList("cars", "bikes/ducati-panigale-1199.jpg", "saint-petersburg.jpg");
UnzipIt.zip(zip).destDir(destDir).settings(settings).extract(fileNames);
```
>```
>filename.zip
>  |-- cars
>  |    |-- bentley-continental.jpg   --> password: 1
>  |    |-- ferrari-458-italia.jpg    --> password: 1
>  |    |-- wiesmann-gt-mf5.jpg       --> password: 1
>  |-- bikes
>  |    |-- ducati-panigale-1199.jpg  --> password: 2
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg           --> password: 3
>```
>```
>/filename_content
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- ducati-panigale-1199.jpg
>  |-- saint-petersburg.jpg
>```

### ZipMisc

#### Modify zip archive comment

```
Path zip = Paths.get("filename.zip");
ZipMisc zipFile = ZipMisc.zip(zip);

zipFile.getComment();           // get current comment (null if it's not set)
zipFile.setComment("comment");  // set comment to 'comment'
zipFile.setComment(null);       // remove comment
```

#### Get all entries

```
Path zip = Paths.get("filename.zip");
ZipMisc zipFile = ZipMisc.zip(zip);
List<ZipFile.Entry> entires = zipFile.getEntries().collect(Collectors.toList());

/*
[entryNames]
cars/bentley-continental.jpg
cars/ferrari-458-italia.jpg
cars/wiesmann-gt-mf5.jpg
bikes/ducati-panigale-1199.jpg
bikes/kawasaki-ninja-300.jpg
saint-petersburg.jpg
*/
```
>```
>filename.zip
> |-- cars
> |    |-- bentley-continental.jpg
> |    |-- ferrari-458-italia.jpg
> |    |-- wiesmann-gt-mf5.jpg
> |-- bikes
> |    |-- ducati-panigale-1199.jpg
> |    |-- kawasaki-ninja-300.jpg
> |-- saint-petersburg.jpg
>```

**Note:** `zipFile.getEntries()` retrieves `Stream` with immutable `ZupFile.Entry` objects represent all entries in zip archive

#### Remove entry by name

```
Path zip = Paths.get("filename.zip");
ZipMisc zipFile = ZipMisc.zip(zip);
zipFile.removeEntryByName("cars/bentley-continental.jpg");
```
>```
>filename.zip (before)
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- bikes
>  |    |-- ducati-panigale-1199.jpg
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg
>```
>```
>filename.zip (after)
>  |-- cars
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- bikes
>  |    |-- ducati-panigale-1199.jpg
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg
>```

**Note:** exactly one entry will be removed in case of entry with exact this name exists

#### Remove some entries by name

```
Path zip = Paths.get("filename.zip");
ZipMisc zipFile = ZipMisc.zip(zip);
Collection<String> entryNames = Arrays.asList("cars/ferrari-458-italia.jpg", "bikes/ducati-panigale-1199.jpg");
zipFile.removeEntryByName(entryNames);
```
>```
>filename.zip (before)
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- bikes
>  |    |-- ducati-panigale-1199.jpg
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg
>```
>```
>filename.zip (after)
>  |-- cars
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- bikes
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg
>```

#### Remove entry by name prefix

```
Path zip = Paths.get("filename.zip");
ZipMisc zipFile = ZipMisc.zip(zip);
zipFile.removeEntryByNamePrefix("cars")
```
>```
>filename.zip (before)
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |    |-- ferrari-458-italia.jpg
>  |    |-- wiesmann-gt-mf5.jpg
>  |-- bikes
>  |    |-- ducati-panigale-1199.jpg
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg
>```
>```
>filename.zip (after)
>  |-- bikes
>  |    |-- ducati-panigale-1199.jpg
>  |    |-- kawasaki-ninja-300.jpg
>  |-- saint-petersburg.jpg
>```

**Note:** multiple entries could be removed

#### Check whether zip archive split or not

```
Path zip = Paths.get("filename.zip");
ZipMisc zipFile = ZipMisc.zip(zip);
boolean split = zipFile.isSplit();
```

#### Merge split archive into solid one

```
Path zipSrc = Paths.get("split.zip");
Path zip = Paths.get("filename.zip");
ZipMisc zipFile = ZipMisc.zip(zipSrc);
zipFile.merge(zip);
```

>```
>/- (before)
> |-- split.z01
> |-- split.z02
> |-- split.z03
> |-- split.zip
>```
>```
>/- (after)
> |-- filename.zip
>```

### ZipInfo

#### Print content of zip file into console
```
Path zip = Paths.get("filename.zip");
ZipInfo.zip(zip).printShortInfo();
```
>```
>filename.zip
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |-- saint-petersburg.jpg
>```
>```
> --- console output ---
>(PK0506) End of Central directory record
>========================================
>    - location:                                     2365537 (0x00241861) bytes
>    - size:                                         22 bytes
>    part number of this part (0000):                1
>    part number of start of central dir (0000):     1
>    number of entries in central dir in this part:  3
>    total number of entries in central dir:         3
>    size of central dir:                            299 (0x0000012B) bytes
>    relative offset of central dir:                 2365238 (0x00241736) bytes
>    zipfile comment length:                         0 bytes
>
>(PK0102) Central directory
>==========================
>    - location:                                     2365238 (0x00241736) bytes
>    - size:                                         303 bytes
>    total entries:                                  3
>
>#1 (PK0102) [UTF-8] cars/
>-------------------------
>    - location:                                     2365238 (0x00241736) bytes
>    - size:                                         87 bytes
>    part number of this part (0000):                1
>    relative offset of local header:                0 (0x00000000) bytes
>    version made by operating system (00):          MS-DOS, OS/2, NT FAT
>    version made by zip software (31):              3.1
>    operat. system version needed to extract (00):  MS-DOS, OS/2, NT FAT
>    unzip software version needed to extract (10):  1.0
>    general purpose bit flag (0x0000) (bit 15..0):  0000.0000 0000.0000
>      file security status  (bit 0):                not encrypted
>      data descriptor       (bit 3):                no
>      strong encryption     (bit 6):                no
>      UTF-8 names          (bit 11):                no
>    compression method (00):                        none (stored)
>    file last modified on (0x5024 0x7EC0):          2020-01-04 15:54:00
>    32-bit CRC value:                               0x00000000
>    compressed size:                                0 bytes
>    uncompressed size:                              0 bytes
>    length of filename:                             5
>                                                    UTF-8
>    63 61 72 73 2F                                  cars/
>    length of file comment:                         0 bytes
>    internal file attributes:                       0x0000
>      apparent file type:                           binary
>    external file attributes:                       0x00000010
>      WINDOWS   (0x10):                             dir
>      POSIX (0x000000):                             ?---------
>    extra field:                                    2365289 (0x00241769) bytes
>      - size:                                       36 bytes (1 record)
>    (0x000A) NTFS Timestamp:                        2365289 (0x00241769) bytes
>      - size:                                       36 bytes
>      - total tags:                                 1
>      (0x0001) Tag1:                                24 bytes
>        Creation Date:                              2020-01-04 12:50:54
>        Last Modified Date:                         2020-01-04 12:54:00
>        Last Accessed Date:                         2020-01-04 12:54:00
>
>#2 (PK0102) [UTF-8] cars/bentley-continental.jpg
>------------------------------------------------
>    - location:                                     2365325 (0x0024178D) bytes
>    - size:                                         110 bytes
>    part number of this part (0000):                1
>    relative offset of local header:                35 (0x00000023) bytes
>    version made by operating system (00):          MS-DOS, OS/2, NT FAT
>    version made by zip software (31):              3.1
>    operat. system version needed to extract (00):  MS-DOS, OS/2, NT FAT
>    unzip software version needed to extract (20):  2.0
>    general purpose bit flag (0x0000) (bit 15..0):  0000.0000 0000.0000
>      file security status  (bit 0):                not encrypted
>      data descriptor       (bit 3):                no
>      strong encryption     (bit 6):                no
>      UTF-8 names          (bit 11):                no
>    compression method (08):                        deflated
>      compression sub-type (deflation):             normal
>    file last modified on (0x4F24 0x3D6D):          2019-09-04 07:43:26
>    32-bit CRC value:                               0x71797968
>    compressed size:                                1380544 bytes
>    uncompressed size:                              1395362 bytes
>    length of filename:                             28
>                                                    UTF-8
>    63 61 72 73 2F 62 65 6E 74 6C 65 79 2D 63 6F 6E cars/bentley-con
>    74 69 6E 65 6E 74 61 6C 2E 6A 70 67             tinental.jpg
>    length of file comment:                         0 bytes
>    internal file attributes:                       0x0000
>      apparent file type:                           binary
>    external file attributes:                       0x00000020
>      WINDOWS   (0x20):                             arc
>      POSIX (0x000000):                             ?---------
>    extra field:                                    2365399 (0x002417D7) bytes
>      - size:                                       36 bytes (1 record)
>    (0x000A) NTFS Timestamp:                        2365399 (0x002417D7) bytes
>      - size:                                       36 bytes
>      - total tags:                                 1
>      (0x0001) Tag1:                                24 bytes
>        Creation Date:                              2020-01-04 12:50:54
>        Last Modified Date:                         2019-09-04 04:43:27
>        Last Accessed Date:                         2020-01-04 12:50:54
>
>#3 (PK0102) [UTF-8] saint-petersburg.jpg
>----------------------------------------
>    - location:                                     2365435 (0x002417FB) bytes
>    - size:                                         102 bytes
>    part number of this part (0000):                1
>    relative offset of local header:                1380637 (0x0015111D) bytes
>    version made by operating system (00):          MS-DOS, OS/2, NT FAT
>    version made by zip software (31):              3.1
>    operat. system version needed to extract (00):  MS-DOS, OS/2, NT FAT
>    unzip software version needed to extract (20):  2.0
>    general purpose bit flag (0x0000) (bit 15..0):  0000.0000 0000.0000
>      file security status  (bit 0):                not encrypted
>      data descriptor       (bit 3):                no
>      strong encryption     (bit 6):                no
>      UTF-8 names          (bit 11):                no
>    compression method (08):                        deflated
>      compression sub-type (deflation):             normal
>    file last modified on (0x4F24 0x3D6D):          2019-09-04 07:43:26
>    32-bit CRC value:                               0x5F2EEF84
>    compressed size:                                984551 bytes
>    uncompressed size:                              1074836 bytes
>    length of filename:                             20
>                                                    UTF-8
>    73 61 69 6E 74 2D 70 65 74 65 72 73 62 75 72 67 saint-petersburg
>    2E 6A 70 67                                     .jpg
>    length of file comment:                         0 bytes
>    internal file attributes:                       0x0000
>      apparent file type:                           binary
>    external file attributes:                       0x00000020
>      WINDOWS   (0x20):                             arc
>      POSIX (0x000000):                             ?---------
>    extra field:                                    2365501 (0x0024183D) bytes
>      - size:                                       36 bytes (1 record)
>    (0x000A) NTFS Timestamp:                        2365501 (0x0024183D) bytes
>      - size:                                       36 bytes
>      - total tags:                                 1
>      (0x0001) Tag1:                                24 bytes
>        Creation Date:                              2020-01-04 12:50:54
>        Last Modified Date:                         2019-09-04 04:43:27
>        Last Accessed Date:                         2020-01-04 12:50:54
>
>(PK0304) ZIP entries
>====================
>    total entries:                                  3
>
>#1 (PK0304) [UTF-8] cars/
>-------------------------
>    - location:                                     0 (0x00000000) bytes
>    - size:                                         35 bytes
>    operat. system version needed to extract (00):  MS-DOS, OS/2, NT FAT
>    unzip software version needed to extract (10):  1.0
>    general purpose bit flag (0x0000) (bit 15..0):  0000.0000 0000.0000
>      file security status  (bit 0):                not encrypted
>      data descriptor       (bit 3):                no
>      strong encryption     (bit 6):                no
>      UTF-8 names          (bit 11):                no
>    compression method (00):                        none (stored)
>    file last modified on (0x5024 0x7EC0):          2020-01-04 15:54:00
>    32-bit CRC value:                               0x00000000
>    compressed size:                                0 bytes
>    uncompressed size:                              0 bytes
>    length of filename:                             5
>                                                    UTF-8
>    63 61 72 73 2F                                  cars/
>
>#2 (PK0304) [UTF-8] cars/bentley-continental.jpg
>------------------------------------------------
>    - location:                                     35 (0x00000023) bytes
>    - size:                                         58 bytes
>    operat. system version needed to extract (00):  MS-DOS, OS/2, NT FAT
>    unzip software version needed to extract (20):  2.0
>    general purpose bit flag (0x0000) (bit 15..0):  0000.0000 0000.0000
>      file security status  (bit 0):                not encrypted
>      data descriptor       (bit 3):                no
>      strong encryption     (bit 6):                no
>      UTF-8 names          (bit 11):                no
>    compression method (08):                        deflated
>      compression sub-type (deflation):             normal
>    file last modified on (0x4F24 0x3D6D):          2019-09-04 07:43:26
>    32-bit CRC value:                               0x71797968
>    compressed size:                                1380544 bytes
>    uncompressed size:                              1395362 bytes
>    length of filename:                             28
>                                                    UTF-8
>    63 61 72 73 2F 62 65 6E 74 6C 65 79 2D 63 6F 6E cars/bentley-con
>    74 69 6E 65 6E 74 61 6C 2E 6A 70 67             tinental.jpg
>
>#3 (PK0304) [UTF-8] saint-petersburg.jpg
>----------------------------------------
>    - location:                                     1380637 (0x0015111D) bytes
>    - size:                                         50 bytes
>    operat. system version needed to extract (00):  MS-DOS, OS/2, NT FAT
>    unzip software version needed to extract (20):  2.0
>    general purpose bit flag (0x0000) (bit 15..0):  0000.0000 0000.0000
>      file security status  (bit 0):                not encrypted
>      data descriptor       (bit 3):                no
>      strong encryption     (bit 6):                no
>      UTF-8 names          (bit 11):                no
>    compression method (08):                        deflated
>      compression sub-type (deflation):             normal
>    file last modified on (0x4F24 0x3D6D):          2019-09-04 07:43:26
>    32-bit CRC value:                               0x5F2EEF84
>    compressed size:                                984551 bytes
>    uncompressed size:                              1074836 bytes
>    length of filename:                             20
>                                                    UTF-8
>    73 61 69 6E 74 2D 70 65 74 65 72 73 62 75 72 67 saint-petersburg
>    2E 6A 70 67                                     .jpg
>```

**Note:** additional method `ZipInfo.printShortInfo(PrintStream)` could be use to print this info to required
`PrintStream`

#### Decompose zip file into `Path` destination
```
Path zip = Paths.get("filename.zip");
Path destDir = Paths.get("/filename_decompose");
ZipInfo.zip(zip).decompose(destDir);
```
>```
>filename.zip
>  |-- cars
>  |    |-- bentley-continental.jpg
>  |-- saint-petersburg.jpg
>```
>```
>/filename_content
>  |-- central_directory
>  |    |-- #1 - cars
>  |    |    |-- extra_fields
>  |    |    |    |-- (0x000A)_NTFS_Timestamp.txt
>  |    |    |    |-- (0x000A)_NTFS_Timestamp.data
>  |    |    |-- file_header.txt
>  |    |    |-- file_header.data
>  |    |-- #2 - cars_-_bentley-continental.jpg
>  |    |    |-- extra_fields
>  |    |    |    |-- (0x000A)_NTFS_Timestamp.txt
>  |    |    |    |-- (0x000A)_NTFS_Timestamp.data
>  |    |    |-- file_header.txt
>  |    |    |-- file_header.data
>  |    |-- #3 - saint-petersburg.jpg
>  |    |    |-- extra_fields
>  |    |    |    |-- (0x000A)_NTFS_Timestamp.txt
>  |    |    |    |-- (0x000A)_NTFS_Timestamp.data
>  |    |    |-- file_header.txt
>  |    |    |-- file_header.data
>  |    |-- central_directory.txt
>  |-- entries
>  |    |-- #1 - cars
>  |    |    |-- local_file_header.txt
>  |    |    |-- local_file_header.data
>  |    |-- #2 - cars_-_bentley-continental.jpg
>  |    |    |-- local_file_header.txt
>  |    |    |-- local_file_header.data
>  |    |-- #3 - saint-petersburg.jpg
>  |    |    |-- file_header.txt
>  |    |    |-- file_header.data
>  |-- end_central_directory.txt
>  |-- end_central_directory.data
>```

## Model

### Zip settings: `ZipSettings`

All zip operations include `ZipSettings`. [Default settings](#zip-settings-defaults) is
used when it's not explicitly set. Settings contains zip archive scope properties as well as
provider for entry specific settings. The key for entry settings is **fileName**.

**Note:** user should not worry about directory marker `/`, because `zip4jvm` does not support
duplicated file names and it's impossible to have same file name for file and directory.

 - _splitSize_ - size of each part in split archive
   - `-1` - no split or solid archive
   - _min size_ - `64Kb` i.e. `65_536`
   - _min size_ - `~2Gb` i.e. `2_147_483_647`
 - _comment_ - global archive comment
   - _no comment_ - `null` or `empty string`
   - _max length_ - `65_535` symbols
 - _zip64_ - use `true` or not `false` zip64 format for global zip structure
   - **Note:** _zip64_ is switched on automatically if needed
   - **Note:** it does not mean that entry structure is in _zip64_ format as well
 - _entrySettingsProvider_ - file name base provider of settings for entry
   - **Note:** each entry could have different settings

#### Zip settings defaults

 - _splitSize_ - `-1`, i.e. off or solid archive
 - _comment_ - `null`, i.e. no comment
 - _zip64_ - `false`, i.e. standard format for global zip structure
 - _entrySettingsProvider_ - `default`, i.e. all entries has same [default entry settings](#zip-entry-settings-defaults)

### Zip entry settings: `ZipEntrySettings`

Each entry has it's own settings. These settings could be different for every entry. If this settings
are not explicitly set, then `default` entry settings are used for all added entries.

 - _compression_ - compression algorithm
   - `store` - no compression
   - `deflate` - use [Deflate](https://en.wikipedia.org/wiki/DEFLATE) compression algorithm
 - _compressionLevel_ - compression level
   - `fastest` `fast` `normal` `maximum` `ultra`
 - _encryption_ - encryption algorithm
   - `off` - not encryption
   - `pkware` - [PKWare](https://en.wikipedia.org/wiki/PKWare) encryption algorithm
   - `aes_128` `aes_192` `aes_256` - [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
     encryption algorithm with given `128` `192` `255` key strength
 - _comment_ - comment for entry
   - _no comment_ - `null` or `empty string`
   - _max length_ - `65_535` symbols
 - _zip64_ - use `true` or not `false` zip64 format for global zip structure
   - **Note:** _zip64_ is switched on automatically if needed
 - _utf8_ - `true` use [UTF8](https://en.wikipedia.org/wiki/UTF-8) charset for file name and comment
   instead of [IBM437](https://en.wikipedia.org/wiki/Code_page_437) when `false`

#### Zip entry settings defaults

 - _compression_ - `deflate`
 - _compressionLevel_ - `normal`
 - _encryption_ - `off`, i.e. no encryption
 - _comment_ - `null`, i.e. no comment
 - _zip64_ - `false`, i.e. standard format for entry structure
 - _utf8_ - `true`, i.e. entry's name and comment are stored using `UTF8` charset

##### Links
* Home page: https://github.com/oleg-cherednik/zip4jvm
* Maven:
  * **central:** https://mvnrepository.com/artifact/ru.oleg-cherednik.zip4jvm/zip4jvm
  * **download:** https://repo1.maven.org/maven2/ru/oleg-cherednik/zip4jvm/zip4jvm/
