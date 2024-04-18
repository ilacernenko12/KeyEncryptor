package org.example;

import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {
        // Два компонента ключа
        String component1 = "7AAFAB94046A4D6B023A50D6831DF9BE";
        String component2 = "EEEA1863F9452A0CB7C41000F5CB136D";

        // Получение байтовых массивов для компонентов ключа
        byte[] bytes1 = DatatypeConverter.parseHexBinary(component1);
        // bytes1[] = [122, -81, -85, -108, 4, 106, 77, 107, 2, 58, 80, -42, -125, 29, -7, -66]
        byte[] bytes2 = DatatypeConverter.parseHexBinary(component2);
        // bytes2[] = [-18, -22, 24, 99, -7, 69, 42, 12, -73, -60, 16, 0, -11, -53, 19, 109]

        // Вычисление ключа (путем применения XOR к каждому байту компонентов)
        byte[] key = new byte[bytes1.length];
        for (int i = 0; i < bytes1.length; i++) {
            key[i] = (byte) (bytes1[i] ^ bytes2[i]);
        }
        // key[] = [-108, 69, -77, -9, -3, 47, 103, 103, -75, -2, 64, -42, 118, -42, -22, -45]

        // Вычисление KCV (путем взятия первых нескольких байтов ключа)
        byte[] kcvMK = calculateKCV(key);
        byte[] kcvComponent1 = calculateKCV(bytes1);
        byte[] kcvComponent2 = calculateKCV(bytes2);

        // Преобразование ключа и KCV в строковое представление
        String generatedKey = DatatypeConverter.printHexBinary(key);

        // Вывод результатов
        System.out.println("Component 1: " + component1);
        System.out.println("Component 2: " + component2);
        System.out.println("Сгенерированный ключ: " + generatedKey);
        System.out.println("Сгенерированный KCV для MasterKey(byte[]): " + Arrays.toString(kcvMK));
        System.out.println("Сгенерированный KCV для MasterKey: " + DatatypeConverter.printHexBinary(kcvMK));
        System.out.println("Сгенерированный KCV для Component 1 (byte[]): " + Arrays.toString(kcvComponent1));
        System.out.println("Сгенерированный KCV для Component 1: " + DatatypeConverter.printHexBinary(kcvComponent1));
        System.out.println("Сгенерированный KCV для Component 2(byte[]): " + Arrays.toString(kcvComponent2));
        System.out.println("Сгенерированный KCV для Component 2: " + DatatypeConverter.printHexBinary(kcvComponent2));
    }

    public static byte[] calculateKCV(byte[] keyBytes) throws Exception {
        // Дополнить ключ до 24 байт, если он меньше
        byte[] fullKeyBytes = new byte[24];
        System.arraycopy(keyBytes, 0, fullKeyBytes, 0, keyBytes.length);
        System.arraycopy(keyBytes, 0, fullKeyBytes, keyBytes.length, 24 - keyBytes.length);

        // Преобразование массива байтов ключа в объект KeySpec
        KeySpec keySpec = new DESedeKeySpec(fullKeyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyFactory.generateSecret(keySpec);

        // Создание Cipher с режимом CBC MAC (Cipher Block Chaining Message Authentication Code)
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]); // Используем пустой IV
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);

        // Вычисление KCV путем шифрования пустых блоков
        byte[] kcv = cipher.doFinal(new byte[8]);

        // Оставляем только первые 3 байта для KCV
        return Arrays.copyOf(kcv, 3);
    }
}