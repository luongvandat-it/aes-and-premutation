package dao;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
/**
 *
 * @author Van Dat
 */
public class AES {

    public AES() {
    }

    public static byte[] SboxTable
            = {0x63, 0x7C, 0x77, 0x7B, (byte) 0xF2, 0x6B, 0x6F,
                (byte) 0xC5, 0x30, 0x01, 0x67, 0x2B, (byte) 0xFE,
                (byte) 0xD7, (byte) 0xAB, 0x76, (byte) 0xCA, (byte) 0x82,
                (byte) 0xC9, 0x7D, (byte) 0xFA, 0x59, 0x47, (byte) 0xF0,
                (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF,
                (byte) 0x9C, (byte) 0xA4, 0x72, (byte) 0xC0, (byte) 0xB7,
                (byte) 0xFD, (byte) 0x93, 0x26, 0x36, 0x3F, (byte) 0xF7,
                (byte) 0xCC, 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1,
                0x71, (byte) 0xD8, 0x31, 0x15, 0x04, (byte) 0xC7,
                0x23, (byte) 0xC3, 0x18, (byte) 0x96, 0x05,
                (byte) 0x9A, 0x07, 0x12, (byte) 0x80, (byte) 0xE2,
                (byte) 0xEB, 0x27, (byte) 0xB2, 0x75, 0x09, (byte) 0x83,
                0x2C, 0x1A, 0x1B, 0x6E, 0x5A, (byte) 0xA0, 0x52, 0x3B,
                (byte) 0xD6, (byte) 0xB3, 0x29, (byte) 0xE3, 0x2F,
                (byte) 0x84, 0x53, (byte) 0xD1, 0x00, (byte) 0xED,
                0x20, (byte) 0xFC, (byte) 0xB1, 0x5B, 0x6A, (byte) 0xCB,
                (byte) 0xBE, 0x39, 0x4A, 0x4C, 0x58, (byte) 0xCF, (byte) 0xD0,
                (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, 0x43, 0x4D, 0x33,
                (byte) 0x85, 0x45, (byte) 0xF9, 0x02, 0x7F, 0x50, 0x3C,
                (byte) 0x9F, (byte) 0xA8, 0x51, (byte) 0xA3, 0x40, (byte) 0x8F,
                (byte) 0x92, (byte) 0x9D, 0x38, (byte) 0xF5, (byte) 0xBC,
                (byte) 0xB6, (byte) 0xDA, 0x21, 0x10, (byte) 0xFF, (byte) 0xF3,
                (byte) 0xD2, (byte) 0xCD, 0x0C, 0x13, (byte) 0xEC, 0x5F,
                (byte) 0x97, 0x44, 0x17, (byte) 0xC4, (byte) 0xA7, 0x7E, 0x3D,
                0x64, 0x5D, 0x19, 0x73, 0x60, (byte) 0x81, 0x4F, (byte) 0xDC,
                0x22, 0x2A, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xEE,
                (byte) 0xB8, 0x14, (byte) 0xDE, 0x5E, 0x0B, (byte) 0xDB,
                (byte) 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
                (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, 0x62, (byte) 0x91,
                (byte) 0x95, (byte) 0xE4, 0x79, (byte) 0xE7, (byte) 0xC8,
                0x37, 0x6D, (byte) 0x8D, (byte) 0xD5, 0x4E, (byte) 0xA9, 0x6C,
                0x56, (byte) 0xF4, (byte) 0xEA, 0x65, 0x7A, (byte) 0xAE, 0x08,
                (byte) 0xBA, 0x78, 0x25, 0x2E, 0x1C, (byte) 0xA6, (byte) 0xB4,
                (byte) 0xC6, (byte) 0xE8, (byte) 0xDD, 0x74, 0x1F, 0x4B,
                (byte) 0xBD, (byte) 0x8B, (byte) 0x8A, 0x70, 0x3E, (byte) 0xB5,
                0x66, 0x48, 0x03, (byte) 0xF6, 0x0E, 0x61, 0x35, 0x57,
                (byte) 0xB9, (byte) 0x86, (byte) 0xC1, 0x1D, (byte) 0x9E,
                (byte) 0xE1, (byte) 0xF8, (byte) 0x98, 0x11, 0x69, (byte) 0xD9,
                (byte) 0x8E, (byte) 0x94, (byte) 0x9B, 0x1E, (byte) 0x87, (byte) 0xE9,
                (byte) 0xCE, 0x55, 0x28, (byte) 0xDF, (byte) 0x8C, (byte) 0xA1,
                (byte) 0x89, 0x0D, (byte) 0xBF, (byte) 0xE6, 0x42, 0x68, 0x41,
                (byte) 0x99, 0x2D, 0x0F, (byte) 0xB0, 0x54, (byte) 0xBB, 0x16};

    public static byte[] SboxTableInv = {0x52, 0x09, 0x6A, (byte) 0xD5,
        0x30, 0x36, (byte) 0xA5, 0x38, (byte) 0xBF, 0x40, (byte) 0xA3,
        (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB, 0x7C,
        (byte) 0xE3, 0x39, (byte) 0x82, (byte) 0x9B, 0x2F, (byte) 0xFF,
        (byte) 0x87, 0x34, (byte) 0x8E, 0x43, 0x44, (byte) 0xC4, (byte) 0xDE,
        (byte) 0xE9, (byte) 0xCB, 0x54, 0x7B, (byte) 0x94, 0x32, (byte) 0xA6,
        (byte) 0xC2, 0x23, 0x3D, (byte) 0xEE, 0x4C, (byte) 0x95, 0x0B, 0x42,
        (byte) 0xFA, (byte) 0xC3, 0x4E, 0x08, 0x2E, (byte) 0xA1, 0x66, 0x28,
        (byte) 0xD9, 0x24, (byte) 0xB2, 0x76, 0x5B, (byte) 0xA2, 0x49, 0x6D,
        (byte) 0x8B, (byte) 0xD1, 0x25, 0x72, (byte) 0xF8, (byte) 0xF6, 0x64,
        (byte) 0x86, 0x68, (byte) 0x98, 0x16, (byte) 0xD4, (byte) 0xA4, 0x5C,
        (byte) 0xCC, 0x5D, 0x65, (byte) 0xB6, (byte) 0x92, 0x6C, 0x70, 0x48,
        0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, 0x5E, 0x15,
        0x46, 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84,
        (byte) 0x90, (byte) 0xD8, (byte) 0xAB, 0x00, (byte) 0x8C,
        (byte) 0xBC, (byte) 0xD3, 0x0A, (byte) 0xF7, (byte) 0xE4, 0x58,
        0x05, (byte) 0xB8, (byte) 0xB3, 0x45, 0x06, (byte) 0xD0, 0x2C,
        0x1E, (byte) 0x8F, (byte) 0xCA, 0x3F, 0x0F, 0x02, (byte) 0xC1,
        (byte) 0xAF, (byte) 0xBD, 0x03, 0x01, 0x13, (byte) 0x8A, 0x6B,
        0x3A, (byte) 0x91, 0x11, 0x41, 0x4F, 0x67, (byte) 0xDC,
        (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE,
        (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, 0x73, (byte) 0x96,
        (byte) 0xAC, 0x74, 0x22, (byte) 0xE7, (byte) 0xAD, 0x35,
        (byte) 0x85, (byte) 0xE2, (byte) 0xF9, 0x37, (byte) 0xE8,
        0x1C, 0x75, (byte) 0xDF, 0x6E, 0x47, (byte) 0xF1, 0x1A, 0x71,
        0x1D, 0x29, (byte) 0xC5, (byte) 0x89, 0x6F, (byte) 0xB7, 0x62,
        0x0E, (byte) 0xAA, 0x18, (byte) 0xBE, 0x1B, (byte) 0xFC, 0x56,
        0x3E, 0x4B, (byte) 0xC6, (byte) 0xD2, 0x79, 0x20, (byte) 0x9A,
        (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, 0x78, (byte) 0xCD, 0x5A,
        (byte) 0xF4, 0x1F, (byte) 0xDD, (byte) 0xA8, 0x33, (byte) 0x88,
        0x07, (byte) 0xC7, 0x31, (byte) 0xB1, 0x12, 0x10, 0x59, 0x27,
        (byte) 0x80, (byte) 0xEC, 0x5F, 0x60, 0x51, 0x7F, (byte) 0xA9,
        0x19, (byte) 0xB5, 0x4A, 0x0D, 0x2D, (byte) 0xE5, 0x7A,
        (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF,
        (byte) 0xA0, (byte) 0xE0, 0x3B, 0x4D, (byte) 0xAE, 0x2A,
        (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB,
        0x3C, (byte) 0x83, 0x53, (byte) 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E,
        (byte) 0xBA, 0x77, (byte) 0xD6, 0x26, (byte) 0xE1, 0x69, 0x14, 0x63,
        0x55, 0x21, 0x0C, 0x7D};

    public static int[] indShiftRow = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
    public static int[] indShiftRowInv = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};

    public static void AddRowKey(byte[] block, byte[] key) {
        for (int i = 0; i < 16; i++) {
            block[i] ^= key[i];
        }
    }

    public static void SubBytes(byte[] block) {
        for (short i = 0; i < 16; i++) {
            block[i] = SboxTable[block[i]];
        }
    }

    public static void ShiftRows(byte[] block) {
        String temp = new String(new char[16]);
        for (int i = 0; i < 16; i++) {
        }

        for (int i = 0; i < 16; i++) {
            block[i] = (byte) temp.charAt(i);
        }
    }

    public static void MixColumns(byte[] block) {
        String temp = new String(new char[4]);
        int p1;
        int p2;
        int p3;
        for (int i = 0; i < 16; i += 4) {
            p1 = i + 1;
            p2 = i + 2;
            p3 = i + 3;

            block[i] = (byte) temp.charAt(0);
            block[p1] = (byte) temp.charAt(1);
            block[p2] = (byte) temp.charAt(2);
            block[p3] = (byte) temp.charAt(3);
        }
    }

    public String encryptAES(String strToEncrypt, String myKey, int optionAES) {
        try {

            String loaiMaHoaAES;
            switch (optionAES) {
                case 0:
                    loaiMaHoaAES = "AES/ECB/PKCS5Padding";
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    byte[] key = myKey.getBytes("UTF-8");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key, 16);
                    SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                    Cipher cipher = Cipher.getInstance(loaiMaHoaAES);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));

                case 1:
                    loaiMaHoaAES = "AES/CBC/PKCS5Padding";
                    String keyCBC = myKey;
                    String initVector = "encryptionIntVec";
                    IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                    SecretKeySpec skeySpec = new SecretKeySpec(keyCBC.getBytes("UTF-8"), "AES");
                    Cipher cipherCBC = Cipher.getInstance(loaiMaHoaAES);
                    cipherCBC.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                    byte[] encrypted = cipherCBC.doFinal(strToEncrypt.getBytes("UTF-8"));
                    return Base64.getEncoder().encodeToString(cipherCBC.doFinal(strToEncrypt.getBytes("UTF-8")));
            }

        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return null;
    }

    public String decryptAES(String strToDecrypt, String myKey, int optionAES) {
        try {
            String loaiMaHoaAES = "";
            switch (optionAES) {
                case 0:
                    loaiMaHoaAES = "AES/ECB/PKCS5Padding";
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    byte[] key = myKey.getBytes("UTF-8");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key, 16);
                    SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                    Cipher cipher = Cipher.getInstance(loaiMaHoaAES);
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                    return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));

                case 1:
                    loaiMaHoaAES = "AES/CBC/PKCS5Padding";
                    String keyCBC = myKey;
                    String initVector = "encryptionIntVec";
                    IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                    SecretKeySpec skeySpec = new SecretKeySpec(keyCBC.getBytes("UTF-8"), "AES");
                    Cipher cipherCBC = Cipher.getInstance(loaiMaHoaAES);
                    cipherCBC.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                    return new String(cipherCBC.doFinal(Base64.getDecoder().decode(strToDecrypt)));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
