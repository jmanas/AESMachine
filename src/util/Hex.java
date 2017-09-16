package util;

import java.math.BigInteger;

/**
 * Created by jose on 12-Jun-17.
 */
public class Hex {
    public static String toString(byte b) {
        return String.format("%02X", b);
    }

    public static String toString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes)
            builder.append(String.format("%02X ", b));
        return builder.toString();
    }

    public static byte toByte(String s) {
        int n0 = Character.digit(s.charAt(0), 16);
        int n1 = Character.digit(s.charAt(1), 16);
        return (byte) ((n0 << 4) + n1);
    }

    public static boolean isHexDigit(char ch) {
        if ('0' <= ch && ch <= '9') return true;
        if ('a' <= ch && ch <= 'f') return true;
        if ('A' <= ch && ch <= 'F') return true;
        return false;
    }

    public static int hex2int(char ch) {
        if ('0' <= ch && ch <= '9') return ch - '0';
        if ('a' <= ch && ch <= 'f') return 10 + ch - 'a';
        if ('A' <= ch && ch <= 'F') return 10 + ch - 'A';
        return 0;
    }

    public static byte[] readBytes(String text) {
        BigInteger n = BigInteger.ZERO;
        int digits = 0;
        for (char ch : text.toCharArray()) {
            if (isHexDigit(ch)) {
                digits++;
                n = n.shiftLeft(4).add(BigInteger.valueOf(hex2int(ch)));
            }
        }
        byte[] bytes0 = n.toByteArray();
        byte[] bytes1 = new byte[(digits + 1) / 2];
        int src = bytes0.length - 1;
        int dst = bytes1.length - 1;
        while (src >= 0 && dst >= 0)
            bytes1[dst--] = bytes0[src--];
        return bytes1;
    }
}