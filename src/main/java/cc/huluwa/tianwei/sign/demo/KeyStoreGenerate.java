package cc.huluwa.tianwei.sign.demo;

import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @Author NieZhiLiang
 * @Email nzlsgg@163.com
 * @GitHub https://github.com/niezhiliang
 * @Date 2019-10-16 2:32 下午
 */
public class KeyStoreGenerate {

    /** 证书容器地址 **/
    private static String KEYSTORE_PATH = "./data/demo.ks";

    /** 密码 **/
    private static String KEYSTORE_PASSWORD = "123456";

    /** 密钥库格式 **/
    private static String KEYSTORE_TYPE = "PKCS12";

    /** pdf路径 **/
    private static String PDF_PATH = "./data/test.pdf";

    /** 签署成功pdf路径 **/
    private static String PDF_SIGNED = "./data/success.pdf";

    /** 签章图片 **/
    private static String SIGN_IMG = "./data/test.png";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static void main(String[] args) throws Exception {
        //生成keystore容器并生成一张证书
        //generateKeyStore();

        //安装第二张证书
        //installSencondCert();

        //pdf证书签署
        signPdf("123456");
    }

    /**
     * 生成keystore容器
     * @throws Exception
     */
    public static void generateKeyStore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null,KEYSTORE_PASSWORD.toCharArray());
        CertAndKeyGen keyGen = new CertAndKeyGen("RSA","SHA1WithRSA",null);
        //CN 姓名  OU 组织单位名称 O 组织名称 L xx ST 省市区名称 C 国家
        X500Name x500Name = new X500Name("聂志良",  "123","456","HangZhou", "ZJ", "CHN");
        //设置加密算法长度
        keyGen.generate(2048);
        PrivateKey privateKey = keyGen.getPrivateKey();
        X509Certificate [] chain =  new X509Certificate[1];
        //设置keystore的有效期限
        chain [0] = keyGen.getSelfCertificate(x500Name,new Date(),1096 * 24 * 60 *60);

        FileOutputStream fileOutputStream = new FileOutputStream(KEYSTORE_PATH);
        //设置第一张初始化证书
        keyStore.setKeyEntry("123456",privateKey,KEYSTORE_PASSWORD.toCharArray(),chain);
        keyStore.store(fileOutputStream,KEYSTORE_PASSWORD.toCharArray());
        fileOutputStream.close();
    }

    /**
     * 安装第二张证书
     */
    public static void installSencondCert() throws Exception {
        InputStream inputStream = new FileInputStream(KEYSTORE_PATH);
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(inputStream,KEYSTORE_PASSWORD.toCharArray());

        CertAndKeyGen keyGen = new CertAndKeyGen("RSA","SHA1WithRSA",null);
        //CN 姓名  OU 组织单位名称 O 组织名称 L xx ST 省市区名称 C 国家
        X500Name x500Name = new X500Name("苏雨",  "567","897","HangZhou", "ZJ", "CHN");
        //设置加密算法长度
        keyGen.generate(2048);
        PrivateKey privateKey = keyGen.getPrivateKey();
        X509Certificate [] chain =  new X509Certificate[1];
        //设置keystore的有效期限
        chain [0] = keyGen.getSelfCertificate(x500Name,new Date(),1096 * 24 * 60 *60);

        FileOutputStream fileOutputStream = new FileOutputStream(KEYSTORE_PATH);
        //设置第一张初始化证书
        keyStore.setKeyEntry("888888",privateKey,"123456".toCharArray(),chain);
        keyStore.store(fileOutputStream,KEYSTORE_PASSWORD.toCharArray());
        fileOutputStream.close();

    }

    /**
     * pdf证书签署
     * @param alias
     * @throws Exception
     */
    public static void signPdf(String alias) throws Exception {
        InputStream inputStream = new FileInputStream(KEYSTORE_PATH);
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(inputStream,KEYSTORE_PASSWORD.toCharArray());

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD.toCharArray());
        //证书链
        Certificate[] chain = keyStore.getCertificateChain(alias);


        String digestAlgorithm = DigestAlgorithms.SHA256;
        MakeSignature.CryptoStandard subfilter = MakeSignature.CryptoStandard.CMS;

        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(PDF_PATH);
        FileOutputStream os = new FileOutputStream(new File(PDF_SIGNED));
        PdfStamper stamper =
                PdfStamper.createSignature(reader, os, '\0', new File("/Users/huluwa/Desktop"), true);
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("签署理由");
        appearance.setLocation("签署位置");

        //设置签名的位置，页码，签名域名称，多次追加签名的时候，签名域名称不能一样
        //签名的位置，是图章相对于pdf页面的位置坐标，原点为pdf页面左下角
        //四个参数的分别是，图章左下角x，图章左下角y，图章右上角x，图章右上角y
        appearance.setVisibleSignature(new Rectangle(50f, 50f , 100f, 100f),
                 1, System.currentTimeMillis()+"");//fileName: 随机作用域

        //签署图片地址
        Image image = Image.getInstance(SIGN_IMG);
        appearance.setSignatureGraphic(image);
        appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
        //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
        // Creating the signature   签名算法
        ExternalSignature pks = new PrivateKeySignature(privateKey, digestAlgorithm, "BC");
        //摘要算法
        ExternalDigest digest = new BouncyCastleDigest();
        // 调用itext签名方法完成pdf签章
        MakeSignature.signDetached(appearance, digest, pks, chain,
                null, null, null, 0, subfilter);

    }
}
