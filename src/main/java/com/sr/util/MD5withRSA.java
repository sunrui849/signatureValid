package com.sr.util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Administrator on 2018/7/21.
 */
public class MD5withRSA {

    public static final String MD_5_WITH_RSA = "MD5withRSA";

    public static  PublicKey publicKey;

    public static  PrivateKey privateKey;

    public static  String signature;

    public static final  String text = "sssss";

    public static void main(String[] args) {
        keyGenerator();
       /* String pubStr = publicKeyToString(publicKey);
        String priStr = privateKeyToString(privateKey);
        publicKey = restorePublicKey(pubStr);
        privateKey = restorePrivateKey(priStr);
        System.out.println(pubStr);
        System.out.println(priStr);*/
        String signature = getMd5Sign(text,privateKey);
        System.out.println(signature);
        boolean verifyWhenMd5Sign = verifyWhenMd5Sign(text,signature,publicKey);
        System.out.println("签名校验："+verifyWhenMd5Sign);


        textWithMD5(text);

    }


    /**
     * 生成公钥私钥
     */
    public static void keyGenerator(){
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024); //可以理解为：加密后的密文长度，实际原文要小些 越大 加密解密越慢
            keyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }


    //生成 MD5withRSA 签名
    static String getMd5Sign(String content , PrivateKey privateKey) {
        String signatureStr = "";
        try {
            byte[] contentBytes = content.getBytes("utf-8");
            Signature signature = Signature.getInstance(MD_5_WITH_RSA);
            signature.initSign(privateKey);
            signature.update(contentBytes);
            byte[] signs = signature.sign();
            signatureStr =  new BASE64Encoder().encode(signs);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signatureStr;
    }

    //对用md5和RSA私钥生成的数字签名进行验证
    static boolean verifyWhenMd5Sign(String content, String sign, PublicKey publicKey) {
        boolean flag = false;
        try {
            flag = false;
            byte[] contentBytes = content.getBytes("utf-8");
            Signature signature = Signature.getInstance(MD_5_WITH_RSA);
            signature.initVerify(publicKey);
            signature.update(contentBytes);
            flag = signature.verify(new BASE64Decoder().decodeBuffer(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return flag;
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


    /*
    *文本 MD5 加密
     */
    public static void textWithMD5(String text){
        try {
            //确定计算方法
            MessageDigest md5=MessageDigest.getInstance("MD5");
            BASE64Encoder base64en = new BASE64Encoder();
            byte[] bytes = md5.digest(text.getBytes("utf-8"));
            //加密后的字符串
            String  result = SHA256withRSA.bytesToHexString(bytes);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
