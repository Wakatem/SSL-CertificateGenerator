

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class CertificateGenerator {

    public CertificateGenerator() {
    }


    //self-signed generated certificate
    public X509Certificate generateSelfSignedCert(String keyAlgorithm, int keySize, SecureRandom random, String signatureAlgorithm, int validityDuration) {

        //generate CSR
        CSRGenerator csrGenerator = new CSRGenerator();
        PKCS10CertificationRequest CSR = csrGenerator.generateCSR(keyAlgorithm, keySize, random, signatureAlgorithm);


        //setup certificate builder
        Date notBefore = getDates(validityDuration)[0];
        Date notAfter = getDates(validityDuration)[1];
        SubjectPublicKeyInfo keyInfo = CSR.getSubjectPublicKeyInfo();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(CSR.getSubject(), new BigInteger(64, random), notBefore, notAfter, CSR.getSubject(), keyInfo);


        //create signer builder
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = null;
        X509Certificate certificate = null;


        //create and sign certificate
        try {
            FileInputStream fis = new FileInputStream("privatekey.key");

            PrivateKey privateKey = KeyFactory.getInstance(keyAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(fis.readAllBytes()));

            signer = signerBuilder.build(privateKey);
            X509CertificateHolder holder = builder.build(signer);
            certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        return certificate;
    }


    //issuer-based generated certificate
    public X509Certificate generateSignedCertificate(PKCS10CertificationRequest CSR, String signatureAlgorithm, SecureRandom random, X500Name issuer, PrivateKey issuerPrivateKey, int duration) {

        //setup certificate builder
        Date notBefore = getDates(duration)[0];
        Date notAfter = getDates(duration)[1];
        SubjectPublicKeyInfo keyInfo = CSR.getSubjectPublicKeyInfo();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, new BigInteger(64, random), notBefore, notAfter, CSR.getSubject(), keyInfo);


        //create signer builder
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = null;
        X509Certificate certificate = null;


        //create and sign certificate
        try {
            signer = signerBuilder.build(issuerPrivateKey);
            X509CertificateHolder holder = builder.build(signer);
            certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return certificate;
    }


    public void exportCertificate(Certificate certificate, File directory, String certificateName) {
        try {
            FileOutputStream out = new FileOutputStream(directory.getAbsoluteFile() + "\\" + certificateName + ".crt");
            out.write(certificate.getEncoded());
            out.flush();
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public boolean CertificateIsVerified(X509Certificate certificate, PublicKey publicKey) {

        boolean verified = false;

        try {
            certificate.verify(publicKey);
            verified = true;
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return verified;
    }


    private Date[] getDates(int duration) {

        Date notBefore = new Date(System.currentTimeMillis());
        long afterValue = TimeUnit.DAYS.toMillis(duration) + notBefore.getTime();
        Date notAfter = new Date(afterValue);

        return new Date[]{notBefore, notAfter};
    }

}
