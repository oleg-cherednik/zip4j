package com.cop.zip4j.io.out;

import com.cop.zip4j.core.writers.ZipModelWriter;
import com.cop.zip4j.exception.Zip4jException;
import com.cop.zip4j.io.out.entry.EntryOutputStream;
import com.cop.zip4j.model.CentralDirectory;
import com.cop.zip4j.model.EndCentralDirectory;
import com.cop.zip4j.model.LocalFileHeader;
import com.cop.zip4j.model.Zip64;
import com.cop.zip4j.model.ZipModel;
import com.cop.zip4j.model.aes.AesExtraDataRecord;
import com.cop.zip4j.utils.InternalZipConstants;
import lombok.NonNull;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Oleg Cherednik
 * @since 08.03.2019
 */
public class SplitZipOutputStream extends BaseMarkDataOutput {

    @NonNull
    private final ZipModel zipModel;

    private int counter;

    @NonNull
    public static SplitZipOutputStream create(@NonNull ZipModel zipModel) throws FileNotFoundException {
        // TODO move to ZipParameters
        if (zipModel.getSplitLength() >= 0 && zipModel.getSplitLength() < InternalZipConstants.MIN_SPLIT_LENGTH)
            throw new Zip4jException("split length less than minimum allowed split length of " + InternalZipConstants.MIN_SPLIT_LENGTH + " Bytes");

        return new SplitZipOutputStream(zipModel);
    }

    private SplitZipOutputStream(@NonNull ZipModel zipModel) throws FileNotFoundException {
        super(zipModel.getZipFile());
        this.zipModel = zipModel;
    }

    @Override
    public void write(byte[] buf, int offs, int len) throws IOException {
        final int offsInit = offs;

        while (len > 0) {
            long canWrite = zipModel.getSplitLength() - getOffs();
            int writeBytes = Math.min(len, (int)canWrite);

            if (canWrite <= 0 || len > canWrite && offsInit != offs && isSignature(buf, offs, len))
                startNextSplitFile();

            delegate.write(buf, offs, writeBytes);

            offs += writeBytes;
            len -= writeBytes;
        }
    }

    private void startNextSplitFile() throws IOException {
        Path currSplitFile = ZipModel.getSplitFilePath(zipFile, ++counter);

        delegate.close();

        if (Files.exists(currSplitFile))
            throw new IOException("split file: " + currSplitFile.getFileName() + " already exists in the current directory, cannot rename this file");

        if (!zipFile.toFile().renameTo(currSplitFile.toFile()))
            throw new IOException("cannot rename newly created split file");

        createDelegate(zipModel.getZipFile());
    }

    @Override
    public void close() throws IOException {
        zipModel.getEndCentralDirectory().setOffs(getOffs());
        new ZipModelWriter(zipModel).finalizeZipFile(this, true);
        delegate.close();
    }

    @Override
    public int getCounter() {
        return counter;
    }

    private static final Set<Integer> SIGNATURES = getAllSignatures();

    private static Set<Integer> getAllSignatures() {
        List<Integer> signatures = Arrays.asList(
                LocalFileHeader.SIGNATURE,
                InternalZipConstants.EXTSIG,
                CentralDirectory.FileHeader.SIGNATURE,
                EndCentralDirectory.SIGNATURE,
                CentralDirectory.DigitalSignature.SIGNATURE,
                InternalZipConstants.ARCEXTDATREC,
                EntryOutputStream.SPLIT_SIGNATURE,
                Zip64.EndCentralDirectoryLocator.SIGNATURE,
                Zip64.EndCentralDirectory.SIGNATURE,
                Zip64.ExtendedInfo.SIGNATURE,
                AesExtraDataRecord.SIGNATURE);

        return Collections.unmodifiableSet(new HashSet<>(signatures));
    }

    private static boolean isSignature(byte[] buf, int offs, int len) {
        return len >= 4 && offs + 4 < buf.length && SIGNATURES.contains(buf[offs + 3] << 24 | buf[offs + 2] << 16 | buf[offs + 1] << 8 | buf[offs]);
    }

}