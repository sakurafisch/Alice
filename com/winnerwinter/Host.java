package com.winnerwinter;

import java.net.DatagramSocket;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.util.Base64;

public class Host extends Thread {
    private DatagramSocket datagramSocket;
    private boolean running;
    private byte[] buf = new byte[65535];
    
    private static String sk;
    public static String pk;
    private static final Path sk_file_path = Path.of("./sk.key");
    public static final Path pk_file_path = Path.of("./pk.crt");

    public static void main(String[] args) throws IOException {
        pk = Files.readString(Host.pk_file_path);
        sk = Files.readString(Host.sk_file_path);
        Host host = new Host();
        host.start();
    }

    public Host() {
        try {
            datagramSocket = new DatagramSocket(4445);
        } catch(SocketException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        running = true;

        while (running) {
            running = false;
            DatagramPacket datagramPacket = new DatagramPacket(buf, buf.length);
            try {
                datagramSocket.receive(datagramPacket);
            } catch (IOException e) {
                e.printStackTrace();
                continue;
            }
            InetAddress address = datagramPacket.getAddress();
            int port = datagramPacket.getPort();
            datagramPacket = new DatagramPacket(buf, buf.length, address, port);
            String received = new String(datagramPacket.getData(), 0, datagramPacket.getLength());

            if (received.charAt(0) == 'B' && received.charAt(1) == 'o' && received.charAt(2) == 'b') {
                System.out.println("Username: Bob");
                StringBuilder password_sb = new StringBuilder();
                for (int i = 3; i < received.length(); ++i) {
                    password_sb.append(received.charAt(i));
                }
                String password = password_sb.toString().trim();
                String password_hashed;
                try {
                    password_hashed = sha1(password);
                } catch (CloneNotSupportedException cnse) {
                    cnse.printStackTrace();
                    continue;
                }
                String password_loaded;
                try {
                    password_loaded = Files.readString(Path.of("./bob_password.hashed.txt"));
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }
                if (!(password_hashed.equals(password_loaded))) {
                    System.out.println("password = " + password);
                    System.out.println("password_hashed = " + password_hashed);
                    System.out.println("password_loaded = " + password_loaded);
                    System.out.println("password is not valid!");
                    byte[] fail = "fail".getBytes();
                    DatagramPacket fail_DatagramPacket = new DatagramPacket(fail, fail.length, address, port);
                    try {
                        datagramSocket.send(fail_DatagramPacket);
                    } catch (IOException e) {
                        e.printStackTrace();
                        continue;
                    }
                    continue;
                }
                System.out.println("password has been verified!");
                String NA = random128string();
                byte[] PK_AND_NA = (pk.concat(NA)).getBytes();
                // datagramPacket.setData(PK_AND_NA);
                datagramPacket = new DatagramPacket(PK_AND_NA, PK_AND_NA.length, address, port);
                try {
                    datagramSocket.send(datagramPacket);
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }
                datagramPacket = new DatagramPacket(buf, buf.length);
                try {
                    datagramSocket.receive(datagramPacket);
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }
                datagramPacket = new DatagramPacket(buf, buf.length, address, port);
                //received = new String(datagramPacket.getData(), 0, datagramPacket.getLength());  // receive ciphertext
                received = new String(datagramPacket.getData());
                String OTP_received = rsa_decrypt(received);
                String OTP_calculated;
                try {
                    String pk_hashed = sha1(pk);
                    System.out.println("NA is " + NA);;
                    OTP_calculated = sha1(pk_hashed + NA);
                } catch (CloneNotSupportedException cnse) {
                    cnse.printStackTrace();
                    continue;
                }
                if (OTP_calculated.equals(OTP_received)) {
                    System.out.println("Success!");
                    byte[] success = "success".getBytes();
                    DatagramPacket success_datagramPacket = new DatagramPacket(success, success.length, address, port);
                    try {
                        datagramSocket.send(success_datagramPacket);
                    } catch (IOException e) {
                        e.printStackTrace();
                        continue;
                    }
                } else {
                    try (PrintWriter out = new PrintWriter("fail_rsa_descrypt_result.txt")) {
                        out.println(OTP_received);
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                        continue;
                    }
                    System.out.println("Fail!");
                    System.out.println("OTP_calculated is " + OTP_calculated);
                    System.out.println("OTP_received is " + OTP_received);
                    byte[] fail = "fail".getBytes();
                    DatagramPacket fail_DatagramPacket = new DatagramPacket(fail, fail.length, address, port);
                    try {
                        datagramSocket.send(fail_DatagramPacket);
                    } catch (IOException e) {
                        e.printStackTrace();
                        continue;
                    }
                    continue;
                }
            } else {
                continue;
            }
        }
        datagramSocket.close();
        System.exit(1);
    }

    private final static PrivateKey getPrivateKey() throws Exception {
        byte[] keyBytes;
        String skPem = sk.replace("-----BEGIN PRIVATE KEY-----", "").replaceAll("\n", "").replace("-----END PRIVATE KEY-----", "").trim();
        keyBytes = Base64.getDecoder().decode(skPem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public final static String rsa_decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
            byte[] deBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext.replaceAll("\r|\n", "").trim()));
            return new String(deBytes);  // Normal return statement
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.exit(1);
        return ciphertext;  // Not reachable
    }

    public final static String sha1(String input_content) throws CloneNotSupportedException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            System.exit(1);
        }
        messageDigest.update(input_content.getBytes());
        byte[] hashed_content = messageDigest.digest();
        return toHexString(hashed_content);
    }

    public final static String random128string() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] b = new byte[16]; // 128 bits is 16 bytes
        secureRandom.nextBytes(b);
        return toHexString(b);
    }

    public final static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
    
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
    
        return hexString.toString();
    }
}
