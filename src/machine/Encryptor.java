package machine;

import se.datadosen.component.RiverLayout;
import util.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.security.SecureRandom;

/**
 * Encryption.
 * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 *
 * @author jose a. manas
 * @version 11.9.2017
 */
public class Encryptor
        implements ActionListener {
    private static final String TITLE = "AES Machine - Encryption (11.9.2017)";
    private static final String PADDING = "PKCS5Padding";

    /*
     * Every implementation of the Java platform is required to support the following standard Cipher transformations with the keysizes in parentheses:
     * AES/CBC/NoPadding (128)
     * AES/CBC/PKCS5Padding (128)
     * AES/ECB/NoPadding (128)
     * AES/ECB/PKCS5Padding (128)
     *
     * https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
     */
    private static final int LINES = 4;

    private static final SecureRandom RANDOM = new SecureRandom();

    private JTextField keyField;
    private JButton keyGenButton;
    private JTextField ivField;
    private JButton ivGenButton;
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
        new Encryptor();
    }

    private Encryptor() {
        JFrame frame = new JFrame(TITLE);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        Container container = frame.getContentPane();

        container.add(new JScrollPane(mkPane()), BorderLayout.CENTER);

        frame.pack();
        frame.setVisible(true);
    }

    private JPanel mkPane() {
        JPanel panel = new JPanel(new RiverLayout());
        panel.add(new JLabel("Encryption"));

        keyField = new JTextField(30);
        keyGenButton = new JButton("generate");
        keyGenButton.addActionListener(this);
        panel.add("p", new JLabel("key: "));
        panel.add("tab", keyField);
        panel.add("tab", keyGenButton);

        ivField = new JTextField(30);
        ivField.setEnabled(false);
        ivGenButton = new JButton("generate");
        ivGenButton.addActionListener(this);
        panel.add("br", new JLabel("IV: "));
        panel.add("tab", ivField);
        panel.add("tab", ivGenButton);

        modeComboBox = new JComboBox<>();
        modeComboBox.addItem("ECB - Electronic Code Book");
        modeComboBox.addItem("CBC - Cypher Block Chaining");
        modeComboBox.addItem("CFB - Cypher Feedback");
        modeComboBox.addItem("OFB - Output Feedback");
        modeComboBox.addItem("CTR - Counter Mode");
        modeComboBox.addItemListener(new MyItemListener());
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
        redInArea = new JTextArea(LINES + 1, 40);
        blackArea = new JTextArea(LINES + 2, 40);   // room for padding
        redOutArea = new JTextArea(LINES + 1, 40);
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

            if (event.getSource() == ivGenButton) {
                byte[] iv = new byte[16];  // 128 bits
                RANDOM.nextBytes(iv);
                ivField.setText(Hex.toString(iv));
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
                byte[] key = getBytes(keyField, 16);
                String mode = getMode();
                byte[] iv = null;
                if (ivField.isEnabled())
                    iv = getBytes(ivField, 16);
                byte[] red = Hex.readBytes(redInArea.getText());

                Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + PADDING);
                SecretKeySpec secretKeySpec = new SecretKeySpec(key, "aes");
                if (iv == null) {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                } else {
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                }
                byte[] black = cipher.doFinal(red);

                writeBytes(blackArea, black);
            }
            if (event.getSource() == decryptButton) {
                redOutArea.setText("");
                byte[] key = getBytes(keyField, 16);
                String mode = getMode();
                byte[] iv = null;
                if (ivField.isEnabled())
                    iv = getBytes(ivField, 16);
                byte[] black = Hex.readBytes(blackArea.getText());

                Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + PADDING);
                SecretKeySpec secretKeySpec = new SecretKeySpec(key, "aes");
                if (iv == null) {
                    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
                } else {
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                }
                byte[] red = cipher.doFinal(black);

                writeBytes(redOutArea, red);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(redInArea, e.getMessage(), TITLE, JOptionPane.ERROR_MESSAGE);
        }
    }

    private String getMode() {
        String s = (String) modeComboBox.getSelectedItem();
        if (s.startsWith("ECB")) return "ECB";
        if (s.startsWith("CBC")) return "CBC";
        if (s.startsWith("CFB")) return "CFB";
        if (s.startsWith("OFB")) return "OFB";
        if (s.startsWith("CTR")) return "CTR";
        return "ECB";
    }

    private byte[] getBytes(JTextField field, int nBytes) {
        byte[] readBytes = Hex.readBytes(field.getText());
        if (readBytes.length == nBytes)
            return readBytes;
        byte[] bytes = new byte[nBytes];
        int src = readBytes.length - 1;
        int dst = bytes.length - 1;
        while (src >= 0 && dst >= 0)
            bytes[dst--] = readBytes[src--];
        field.setText(Hex.toString(bytes));
        return bytes;
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

    private class MyItemListener
            implements java.awt.event.ItemListener {
        @Override
        public void itemStateChanged(ItemEvent e) {
            String mode = (String) modeComboBox.getSelectedItem();
            if (mode.startsWith("ECB"))
                ivField.setEnabled(false);
            else
                ivField.setEnabled(true);
        }
    }
}
