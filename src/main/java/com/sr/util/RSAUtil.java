package com.sr.util;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 非对称加密
 */
public class RSAUtil {
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static final int KEY_SIZE = 2048;

    static{
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 加密
     * @param content 需要加密内容
     * @return
     */
    public static byte[] encrypt(byte[] content) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipherDoFinal(cipher, content, KEY_SIZE/8 - 11);
    }

    /**
     * 解密
     * @param content 加密内容
     * @return
     */
    public static byte[] decrypt(byte[] content) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipherDoFinal(cipher, content, KEY_SIZE/8);
    }

    /**
     * 分段加解密处理方法
     * @param cipher 密码，需要初始化是加密还是解密
     * @param srcBytes 加密（解密）字节
     * @return
     * @throws Exception
     */
    private static byte[] cipherDoFinal(Cipher cipher, byte[] srcBytes, int segmentSize) throws Exception{
        if (segmentSize <= 0){
            // 无须分段
            return cipher.doFinal(srcBytes);
        }

        byte[] data = new byte[0];

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()){
            int inputLen = srcBytes.length;
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                // 从srcBytes中每次取出segmentSize字节进行加密，直到取完
                if (inputLen - offSet > segmentSize) {
                    cache = cipher.doFinal(srcBytes, offSet, segmentSize);
                } else {
                    cache = cipher.doFinal(srcBytes, offSet, inputLen - offSet);
                }
                out.write(cache);
                offSet = ++i * segmentSize;
            }
            data = out.toByteArray();
        }catch (Exception e){
            e.printStackTrace();
        }

        return data;
    }


    /**
     * 从证书里面获取公钥
     * @param cerPath 证书路径
     * @return
     * @throws Exception
     */
    private static PublicKey getPublicKey(String cerPath) throws Exception {
        CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(cerPath);
        X509Certificate Cert = (X509Certificate) certificatefactory.generateCertificate(fis);
        return Cert.getPublicKey();
    }

    /**
     * 从秘钥库里获取私钥
     * @param storePath 秘钥库文件路径
     * @param alias 秘钥别名
     * @param storePw 秘钥库密码
     * @param keyPw 秘钥密码
     * @return
     * @throws Exception
     */
    private static PrivateKey getPrivateKey(String storePath, String alias, String storePw, String keyPw) throws Exception {
        FileInputStream is = new FileInputStream(storePath);
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(is, storePw.toCharArray());
        is.close();
        return (PrivateKey) ks.getKey(alias, keyPw.toCharArray());
    }

    public static void main(String[] args) throws Exception{
        byte[] encryptBytes = encrypt("sunrui".getBytes());
        System.out.println(new String(encryptBytes)); // 打印乱码，可以在加密完成后进行一次base64编码，在解密前在进行一次base64解码，即展示成字符串
        byte[] decryptBytes = decrypt(encryptBytes);
        System.out.println(new String(decryptBytes));
    }

    private RSAUtil(){
        // do nothing
    }
}