import org.apache.commons.codec.binary.Hex;

import org.mozilla.jss.*;
import org.mozilla.jss.util.*;

import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.*;

public class Reproducer {
    public static void initializeCM(String database, String password) throws Exception {
        CryptoManager manager;
        CryptoManager.initialize(database);
        manager = CryptoManager.getInstance();
        if (!password.isEmpty()) {
            manager.setPasswordCallback(new Password(password.toCharArray()));
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1) {
            initializeCM(args[0], "");
        } else if (args.length == 2) {
            initializeCM(args[0], args[1]);
        }

        String keyHex1 = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100803a7b89af4ff74b3c41aeee65fd75bcdaf94b41bfb63d08c28a8110a50db582acab0a07365e5e485a0c7f6c794769de6e8e50d832ff567718a17f6b6c5628cd3ae978b21c94947a091cfdf8b202bedccc7b37b545edd251374770c3481706d0eafbed8aeb1c53b4c058283314238c4e9075970105379e291ac49b1393881faf75ecbd302a01c21a6bebdbff72f53323543fdb9cd74c24223746b118c92d9ef62a5654d426db4261ec478d07c79dfdd0850bef6cc7b8cc55a1927154e5b28d23cdca52a6d7d7f887388624412b1d4af5291d2b4446a236f42c3b4aa010e2916966ad64a410e4c99457c291ce110800d5514da9881126848414ffb58eb5a5c11b5e00c7d241f2dced704d74434792ab4b5aadbb988aa4ce93ce094e6c8e2036b05e4540f98c5406d8b048136a6fbb1f10a34203d932d3c1e8f0f62b602421c365fa44b92e69a7195b811b16f86050b04d44c817454564f7e2987732b8952ed30480a87cfdb42d09dc6170f10237f7121246dc2656f15896c25c36e8f969e38ab1a0a309deab9de00bbd9c4d5938abec6236264c07ac523a4b220377d42e0690c07df58a1143e9967460e160ef76ddece445648a558a0789c2e4bc9e02af4b3a1995f5a26bd6e2708284701c274aa5b0f6207b84b93825ff9c97ce53bb82b1fa599df6b009af621ae06a30fb199e52ea3cd5b77a3f13a9df87fafdcf55f1e8cf8f0203010001";
        String keyHex2 = "30820222300d06092a864886f70d01010105000382020f003082020a02820201008c0b7b78e5e25fb583f5230b738097b4910c1248808146c923f185010cf0151c082d426d9129922f3c44205f4d8dbc8b812b59c245a587141cd432cc3bf22aa3213a203812f73119ffc69552bc7c4fcebc3c04e9e800670461e685cb1f91c492bc35e9f0795a3261291957266bea44d12fa77fd125d02bc207954103a78e8f7cee1ee2d52231b6c788decf5a31a14580bfea1d672ca273bb52e021ffd5fe243254516be7c7589d02587f7964bbf5578ce4bef5d348b7b74467acf5af172dd6779d80b8d3c9243891294fd1c93c2549623fbac5c1208e2074e9912cbea3553c8c9657b3ea4692ceca905790bb546fa148d821b5e0083fcef5306a5c4e441a67518313ef02ffa5c201d3b794002b295b66e79b9127542c188beba57cafce099d88b4eaaf9519a234c337c3e49dc0296ca1a38f0ee841746b786daadd18d159202b23fe1d22ac89d419b449d6d28783cff7e757fefbcc5b49f562be995d60f43b6e92c5339877c1a796346f6cff9e87f816109be6abbf9c436951427ae864e3b1875f0aecfeb6ee1d12423da7ab5432052cb3af57db5b158303afc53556d0297ef10890926a281072f7a6dd1dcc1969d63a41aa68d7c65d71737bafb1aadef1aedc612e11b12e292f8477a5569c141759c3d1600618d9a1430f682680fd6d18d3c179666c3d57f138ee7554bca033190eb29abf82a820e3cba2acc5525ac573b9a90203010001";
        String keyHex3 = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100c5bbf24d3976b1bb2cce2cd728f65f63f354c8031aac451a473360af4a56059a6bd619a1bb21ea1b27777780957c68a8059a6eea78b1506b3e9b3369f83973b9387bcf4a3a45ae509d9886ed802a238bed73dabcfbf13a6ebea52616819fd0b2449df3dabc2420b47ee379640101978f835e3ef394264636202f2c3bd4abc1f144311c89e3d89eab665c008d227a49ecea4074b31a1d0cb2c89867d3ec1b78aea55a6d85d4ece91fe406511aae3e341dd2bc707cf7ba5c8c0ec77f97f5553d8a781f9b59e0784b364a328f6a3fae9e721c2b88d431bb02506c5f50babe17ea0f7e6a27bd4349af8f549741b84bc90f4ed3b21d8fb628ad8263b2502056f60a7cc656226e8fdd0f13615210a6885011b1a63ed01506d9449f52ef4b803c4cc0cb831f2a04a624c95ea9bfd17b2bcc9d8a9e4b354d0e8776d2e8534e1d4b73a72ca52c19515a5ce4f9a1a35789356081362b518e556f27677deab617fd0c9bd0be54da132303118f6ad919bcf5c2a26a6f0a629296f2031290440dbfe6082ad2978e09db2ace2cef8e039175ee1be7f34fb8a65fb50c11fa96a8b7d234247818666475bdb9dd05aa214ab31017b4fbaf838ee0ad2ecf49d54b45dc61ff413d5fb45fc2ac4aca094b7682d6dd8865cfe13bd90275b011aec30dffce29485fb46f982a1a154c7dfa1c5d16543e91f615125a9daab8bfcbaac11122ecd81dc37356a70203010001";

        System.out.println("keys equal? " + (keyHex1.equals(keyHex2)));

        doSomething(keyHex1);
        doSomething(keyHex2);
        doSomething(keyHex3);
    }

    public static void doSomething(String keyHex) throws Exception {
        X509CertInfo certInfo = new X509CertInfo();

        byte[] publicKeyEncoded = Hex.decodeHex(keyHex.toCharArray());
        System.out.println("PublicKey: " + publicKeyEncoded);

        DerValue dvPublicKey = new DerValue(publicKeyEncoded);
        System.out.println("DerValue PublicKey: " + dvPublicKey);

        X509Key key = X509Key.parse(dvPublicKey);
        System.out.println("key: " + key);

        CertificateX509Key certKey = new CertificateX509Key(key);
        certInfo.set(X509CertInfo.KEY, certKey);

        System.out.println(certKey);
    }
}
