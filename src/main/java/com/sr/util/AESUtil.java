package com.sr.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

/**
 * 对称加密 AES
 */
public class AESUtil {
    private static final String ENCRYPTION_MODE = "AES";

    /**
     * 加密
     * @param content
     * @param password
     * @return
     */
    public static String encrypt(String content, String password) {
        try {
            SecretKeySpec key = getSecretKeySpec(password);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_MODE);// 创建密码器
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化 设置为加密
            byte[] byteContent = content.getBytes(StandardCharsets.UTF_8);
            byte[] encryptResult = cipher.doFinal(byteContent);
            return Base64.encode(encryptResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     * @param content
     * @param password
     * @return
     */
    public static String decrypt(String content, String password) {
        try {
            SecretKeySpec key = getSecretKeySpec(password);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_MODE);// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化 设置为解密
            byte[] bytes = Base64.decode(content);
            return new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 根据密码获取秘钥
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static SecretKeySpec getSecretKeySpec(String password) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_MODE);
        keyGenerator.init(128, new SecureRandom(password.getBytes()));
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] enCodeFormat = secretKey.getEncoded();
        return new SecretKeySpec(enCodeFormat, ENCRYPTION_MODE);
    }

    public static void main(String[] args) {
        String password = "123456798"; // 密码
        String content = "sunrui"; // 要加密内容
        String encryptStr = encrypt(content, password); // 加密后内容
        System.out.println(encryptStr);
        String decryptStr = decrypt(encryptStr, password);// 解密后内容
        System.out.println(decryptStr);
    }
}
