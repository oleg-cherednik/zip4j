/*
 * Copyright 2010 Srikanth Reddy Lingala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.lingala.zip4j.util;

import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang.StringUtils;

import java.nio.charset.Charset;
import java.util.Calendar;

/**
 * @author Oleg CHerednik
 * @since 20.03.2019
 */
@UtilityClass
public class ZipUtils {

    /**
     * Converts input time from Java to DOS format
     *
     * @param time
     * @return time in DOS format
     */
    public long javaToDosTime(long time) {

        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(time);

        int year = cal.get(Calendar.YEAR);
        if (year < 1980) {
            return (1 << 21) | (1 << 16);
        }
        return (year - 1980) << 25 | (cal.get(Calendar.MONTH) + 1) << 21 |
                cal.get(Calendar.DATE) << 16 | cal.get(Calendar.HOUR_OF_DAY) << 11 | cal.get(Calendar.MINUTE) << 5 |
                cal.get(Calendar.SECOND) >> 1;
    }

    /**
     * Converts time in dos format to Java format
     *
     * @param dosTime
     * @return time in java format
     */
    public static long dosToJavaTme(int dosTime) {
        int sec = 2 * (dosTime & 0x1f);
        int min = (dosTime >> 5) & 0x3f;
        int hrs = (dosTime >> 11) & 0x1f;
        int day = (dosTime >> 16) & 0x1f;
        int mon = ((dosTime >> 21) & 0xf) - 1;
        int year = ((dosTime >> 25) & 0x7f) + 1980;

        Calendar cal = Calendar.getInstance();
        cal.set(year, mon, day, hrs, min, sec);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTime().getTime();
    }

    /**
     * returns the length of the string in the input encoding
     *
     * @param str
     * @param charset
     * @return int
     */
    public static int getEncodedStringLength(String str, @NonNull Charset charset) {
        return StringUtils.isBlank(str) ? 0 : str.getBytes(charset).length;
    }

    public static long[] getAllHeaderSignatures() {
        long[] allSigs = new long[11];

        allSigs[0] = InternalZipConstants.LOCSIG;
        allSigs[1] = InternalZipConstants.EXTSIG;
        allSigs[2] = InternalZipConstants.CENSIG;
        allSigs[3] = InternalZipConstants.ENDSIG;
        allSigs[4] = InternalZipConstants.DIGSIG;
        allSigs[5] = InternalZipConstants.ARCEXTDATREC;
        allSigs[6] = InternalZipConstants.SPLITSIG;
        allSigs[7] = InternalZipConstants.ZIP64_ENDSIG_LOC;
        allSigs[8] = InternalZipConstants.ZIP64_ENDSIG;
        allSigs[9] = InternalZipConstants.EXTRAFIELDZIP64LENGTH;
        allSigs[10] = InternalZipConstants.AESSIG;

        return allSigs;
    }

    public static boolean isDirectory(String fileName) {
        return fileName != null && (fileName.endsWith("/") || fileName.endsWith("\\"));
    }
}