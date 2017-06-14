package machine;

import se.datadosen.component.RiverLayout;
import util.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

/**
 * Authenticated encryption.
 * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 *
 * @author jose a. manas
 * @date 12.6.2017
 */
public class AuthEnc
        implements ActionListener {
    private static final String TITLE = "AES Machine - Authenticated Encryption (12.6.2017)";
    private static final String PADDING = "NoPadding";

    private static final int LINES = 5;

    private static final SecureRandom RANDOM = new SecureRandom();

    private JTextField keyField;
    private JButton keyGenButton;
    private JTextField nonceField;
    private JButton nonceGenButton;
    private JTextField tagField;
    private JButton zeroRedButton;
    private JButton serieRedButton;
    private JButton patternRedButton;
    private JButton randomRedButton;
    private JTextArea redInArea;
    private JButton encryptButton;
    private JTextArea blackArea;
    private JButton decryptButton;
    private JTextArea redOutArea;
    private JComboBox<String> modeComboBox;

    public static void main(String[] args) {
        new AuthEnc();
    }

    private AuthEnc() {
        JFrame frame = new JFrame(TITLE);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        Container container = frame.getContentPane();

        container.add(new JScrollPane(mkPane()), BorderLayout.CENTER);

        frame.pack();
        frame.setVisible(true);
    }

    private JPanel mkPane() {
        JPanel panel = new JPanel(new RiverLayout());
        panel.add(new JLabel("Authenticated encryption"));

        keyField = new JTextField(30);
        keyGenButton = new JButton("generate");
        keyGenButton.addActionListener(this);
        panel.add("p", new JLabel("key: "));
        panel.add("tab", keyField);
        panel.add("tab", keyGenButton);

        nonceField = new JTextField(30);
        nonceGenButton = new JButton("generate");
        nonceGenButton.addActionListener(this);
        panel.add("br", new JLabel("nonce: "));
        panel.add("tab", nonceField);
        panel.add("tab", nonceGenButton);

        tagField = new JTextField(30);
//        tagGenButton = new JButton("generate");
//        tagGenButton.addActionListener(this);
        panel.add("br", new JLabel("tag: "));
        panel.add("tab", tagField);
//        panel.add("tab", tagGenButton);
        panel.add("tab", new JLabel("authenticated data"));

        modeComboBox = new JComboBox<>();
//        modeComboBox.addItem("CCM - Counter with CBC-MAC");
        modeComboBox.addItem("GCM - Galois Counter Mode");
        panel.add("br tab", modeComboBox);

        panel.add("p vtop", new JLabel("red data: "));
        zeroRedButton = new JButton("0's");
        serieRedButton = new JButton("01 02 03 ...");
        patternRedButton = new JButton("pattern");
        randomRedButton = new JButton("random");
        zeroRedButton.addActionListener(this);
        serieRedButton.addActionListener(this);
        patternRedButton.addActionListener(this);
        randomRedButton.addActionListener(this);
        encryptButton = new JButton("encrypt");
        decryptButton = new JButton("decrypt");
        encryptButton.addActionListener(this);
        decryptButton.addActionListener(this);
        redInArea = new JTextArea(LINES, 40);
        blackArea = new JTextArea(LINES, 40);
        redOutArea = new JTextArea(LINES, 40);
        panel.add("tab", zeroRedButton);
        panel.add(serieRedButton);
        panel.add(patternRedButton);
        panel.add(randomRedButton);
        panel.add("p tab", redInArea);
        panel.add("p vtop", encryptButton);
        panel.add("tab", blackArea);
        panel.add("p vtop", decryptButton);
        panel.add("tab", redOutArea);

        Border border = BorderFactory.createEmptyBorder(10, 5, 10, 5);
        panel.setBorder(border);
        return panel;
    }

    @Override
    public void actionPerformed(ActionEvent event) {
        try {
            if (event.getSource() == keyGenButton) {
                byte[] key = new byte[16];  // 128 bits
                RANDOM.nextBytes(key);
                keyField.setText(Hex.toString(key));
            }

            if (event.getSource() == nonceGenButton) {
                byte[] iv = new byte[16];  // 128 bits
                RANDOM.nextBytes(iv);
                nonceField.setText(Hex.toString(iv));
            }

            if (event.getSource() == zeroRedButton) {
                redInArea.setText("");
                for (int row = 0; row < LINES; row++) {
                    byte[] data = new byte[16];  // 128 bits
                    redInArea.append(Hex.toString(data));
                    redInArea.append("\n");
                }
            }
            if (event.getSource() == serieRedButton) {
                redInArea.setText("");
                byte cnt = 0;
                for (int row = 0; row < LINES; row++) {
                    byte[] data = new byte[16];  // 128 bits
                    for (int i = 0; i < data.length; i++)
                        data[i] = cnt++;
                    redInArea.append(Hex.toString(data));
                    redInArea.append("\n");
                }
            }
            if (event.getSource() == patternRedButton) {
                redInArea.setText("");
                byte[] data = new byte[16];  // 128 bits
                RANDOM.nextBytes(data);
                for (int row = 0; row < LINES; row++) {
                    redInArea.append(Hex.toString(data));
                    redInArea.append("\n");
                }
            }
            if (event.getSource() == randomRedButton) {
                redInArea.setText("");
                for (int row = 0; row < LINES; row++) {
                    byte[] data = new byte[16];  // 128 bits
                    RANDOM.nextBytes(data);
                    redInArea.append(Hex.toString(data));
                    redInArea.append("\n");
                }
            }

            if (event.getSource() == encryptButton) {
                blackArea.setText("");
                byte[] key = readBytes(keyField.getText());
                String mode = getMode();
                byte[] nonce = readBytes(nonceField.getText());
                byte[] aad = getAAD(tagField.getText());
                byte[] red = readBytes(redInArea.getText());

                Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + PADDING);
                SecretKeySpec secretKeySpec = new SecretKeySpec(key, "aes");
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(aad.length * 8, nonce);
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
                cipher.updateAAD(aad);
                byte[] black = cipher.doFinal(red);

                writeBytes(blackArea, black);
            }
            if (event.getSource() == decryptButton) {
                redOutArea.setText("");
                byte[] key = readBytes(keyField.getText());
                String mode = getMode();
                byte[] nonce = readBytes(nonceField.getText());
                byte[] aad = getAAD(tagField.getText());
                byte[] black = readBytes(blackArea.getText());

                Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + PADDING);
                SecretKeySpec secretKeySpec = new SecretKeySpec(key, "aes");
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(aad.length * 8, nonce);
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
                cipher.updateAAD(aad);
                byte[] red = cipher.doFinal(black);

                writeBytes(redOutArea, red);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(redInArea, e.getMessage(), TITLE, JOptionPane.ERROR_MESSAGE);
        }
    }

    private String getMode() {
        String s = (String) modeComboBox.getSelectedItem();
        if (s.startsWith("CCM")) return "CCM";
        if (s.startsWith("GCM")) return "GCM";
        return "GCM";
    }

    private byte[] readBytes(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String s = "";
        for (char ch : text.toCharArray()) {
            if (!isHexDigit(ch))
                continue;
            s += ch;
            if (s.length() == 2) {
                out.write(Hex.toByte(s));
                s = "";
            }
        }
        return out.toByteArray();
    }

    private boolean isHexDigit(char ch) {
        if ('0' <= ch && ch <= '9') return true;
        if ('a' <= ch && ch <= 'f') return true;
        if ('A' <= ch && ch <= 'F') return true;
        return false;
    }

    private byte[] getAAD(String text) {
        byte[] input = readBytes(text);
        int tlen = 128 / 8; // max: 128 bits
        if (input.length < 120 / 8)
            tlen = 120 / 8;
        if (input.length < 112 / 8)
            tlen = 112 / 8;
        if (input.length < 104 / 8)
            tlen = 104 / 8;
        if (input.length < 96 / 8)
            tlen = 96 / 8;
        byte[] aad = new byte[tlen];
        System.arraycopy(input, 0, aad, 0, Math.min(input.length, tlen));
        return aad;
    }

    private void writeBytes(JTextArea area, byte[] bytes) {
        area.setText("");
        int cols = 0;
        for (byte b : bytes) {
            area.append(Hex.toString(b));
            area.append(" ");
            cols++;
            if (cols == 16) {
                area.append("\n");
                cols = 0;
            }
        }
    }
}
