package ru.olegcherednik.zip4jvm.io.lzma.lz;

import lombok.Getter;
import lombok.Setter;

/**
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
@Getter
public final class Matches {

    private final int[] len;
    private final int[] dist;
    @Setter
    private int count;

    Matches(int maxCount) {
        len = new int[maxCount];
        dist = new int[maxCount];
    }

    public void incCount() {
        count++;
    }

    public void decCount() {
        count--;
    }
}
