package com.sr.util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Administrator on 2018/7/21.
 */
public class SHA256withRSA {

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static PublicKey publicKey;

    public static PrivateKey privateKey;

    public static  String signature;

    public static final  String text = "aaaaa";


    public static void main(String[] args) {
        keyGenerator();

      /*  String pubStr = publicKeyToString(publicKey);
        String priStr = privateKeyToString(privateKey);
        publicKey = restorePublicKey(pubStr);
        privateKey = restorePrivateKey(priStr);
        System.out.println(pubStr);
        System.out.println(priStr);*/

        signature = sign(privateKey,text);

        verifySign(publicKey,text,signature);

        /**
         * 如果文本需要加密的话，那么在生成签名前将文本加密后生成签名，并在验证签名时将文本加密后在校验
         */
//        textWithSHA256(text);

    }


    /**
     * 生成密钥
     */
    public static void keyGenerator(){
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 签名
     *
     * @param privateKey
     *            私钥
     * @param plain_text
     *            明文
     * @return
     */
    public static String sign(PrivateKey privateKey, String plain_text) {
         String signetureStr = null;
        try {
            Signature Sign = Signature.getInstance(SIGNATURE_ALGORITHM);
            Sign.initSign(privateKey);
            Sign.update(plain_text.getBytes());
            byte[] signed = Sign.sign();
            signetureStr = DatatypeConverter.printBase64Binary(signed);
//            new BASE64Encoder().encode(signed);
            System.out.println("签名："+signetureStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signetureStr;
    }

    /**
     * 验签
     *
     * @param publicKey
     *            公钥
     * @param plain_text
     *            明文
     * @param signature
     *            签名
     */
    public static boolean verifySign(PublicKey publicKey, String plain_text, String signature) {

        boolean SignedSuccess=false;
        try {
            Signature verifySign = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifySign.initVerify(publicKey);
            verifySign.update(plain_text.getBytes());
            SignedSuccess = verifySign.verify(new BASE64Decoder().decodeBuffer(signature));
            System.out.println("验证成功？---" + SignedSuccess);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return SignedSuccess;
    }


    /**
     * 公钥转字符串
     * @param publicKey
     * @return
     */
    public static String publicKeyToString(PublicKey publicKey){
        byte[] publicBT = publicKey.getEncoded();
        String pubStr = new BASE64Encoder().encode(publicBT);

        return  pubStr;
    }

    /**
     * 私钥转字符串
     * @param privateKey
     * @return
     */
    public static String privateKeyToString(PrivateKey privateKey){
        byte[] privateBT = privateKey.getEncoded();
        String priStr = new BASE64Encoder().encode(privateBT);
        return  priStr;
    }


    /*
   将字符串转公钥
    */
    public static PublicKey restorePublicKey(String str) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(new BASE64Decoder().decodeBuffer(str));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            publicKey = factory.generatePublic(x509EncodedKeySpec);
            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /*
    *将字符串转私钥
   */
    public static PrivateKey restorePrivateKey(String str) {
        PrivateKey privateKey = null;
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(str));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            privateKey = factory.generatePrivate(pkcs8EncodedKeySpec);
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }


    /**
     * 将文本用 sha-256 加密
     * @param text
     * @return
     */
    public static byte[] textWithSHA256(String text) {
        byte[] outputDigest_sign = null;
        try {
            MessageDigest messageDigest;
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(text.getBytes());
            outputDigest_sign = messageDigest.digest();
            System.out.println("SHA256加密后文本："+bytesToHexString(outputDigest_sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return outputDigest_sign;
    }





    /**
     * bytes[]换成16进制字符串
     *
     * @param src
     * @return
     */
    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }
}
