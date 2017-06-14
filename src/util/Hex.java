package util;

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
}