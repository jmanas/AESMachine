package util;

import java.util.ArrayList;

/**
 * Created by jose on 12-Jun-17.
 */
public class Hex {
    public static String toString(byte b) {
        return String.format("%02X", b);
    }

    public static String toString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b: bytes)
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
        ArrayList<Byte> byteList = new ArrayList<>();
        boolean even = true;
        for (char ch : text.toCharArray()) {
            if (!isHexDigit(ch))
                continue;
            byte b;
            if (even) {
                b = (byte) (hex2int(ch) << 4);
            } else {
                b = byteList.remove(byteList.size()-1);
                b = (byte) (b + hex2int(ch));
            }
            byteList.add(b);
            even = !even;
        }
        byte[] bytes = new byte[byteList.size()];
        for (int i = 0; i < bytes.length; i++)
            bytes[i] = byteList.get(i);
        return bytes;
    }
}