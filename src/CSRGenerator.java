import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.util.Scanner;

public class CSRGenerator {


    public PKCS10CertificationRequest generateCSR(String algorithm, int keySize, SecureRandom random, String signatureAlgorithm) {


        //prepare keypair
        KeyPair keyPair = prepareKeyPair(algorithm, keySize, random);

        //prepare subject details
        X500Name subject = prepareSubject();

        //prepare signer
        ContentSigner signer = prepareSigner(signatureAlgorithm, keyPair);

        //create and sign CSR
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        PKCS10CertificationRequest CSR = csrBuilder.build(signer);


        return CSR;
    }

    public PKCS10CertificationRequest importCSR(File path){
        try (FileInputStream  fis = new FileInputStream(path)){
            byte[] bytes = fis.readAllBytes();
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(bytes);
            return csr;

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }


    public PKCS10CertificationRequest importCSR(FileInputStream fis){
        try {
            byte[] bytes = fis.readAllBytes();
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(bytes);
            return csr;

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    public void exportCSR(PKCS10CertificationRequest CSR, File directory, String csrName) {

        try {
            FileOutputStream out = new FileOutputStream(directory.getAbsoluteFile() + "\\" + csrName + ".csr");
            out.write(CSR.getEncoded());
            out.flush();
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public boolean CSRisVerified(PKCS10CertificationRequest CSR, PublicKey publicKey) {

        boolean verified = false;
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(publicKey);
            CSR.isSignatureValid(verifier);
            verified = true;
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (PKCSException e) {
            e.printStackTrace();
        }

        return verified;
    }

    private KeyPair prepareKeyPair(String algorithm, int keySize, SecureRandom random) {
        KeyPairGenerator generator;

        try {
            generator = KeyPairGenerator.getInstance(algorithm);
            generator.initialize(keySize, random);
            KeyPair pair = generator.generateKeyPair();

            FileOutputStream keyOut;

            //export private key
            keyOut = new FileOutputStream("privatekey.key");
            keyOut.write(pair.getPrivate().getEncoded());
            keyOut.flush();

            //export public key
            keyOut = new FileOutputStream("publickey.key");
            keyOut.write(pair.getPublic().getEncoded());
            keyOut.flush();

            keyOut.close();
            return pair;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


        return null;
    }

    private X500Name prepareSubject() {

        X500NameBuilder builder = new X500NameBuilder();

        Scanner input = new Scanner(System.in);
        System.out.println("Enter the following details (* indicates to a mandatory field) | (enter . if field not needed)");
        String[] fields = new String[7];

        System.out.print("* Common Name (CN): ");
        fields[0] = input.nextLine();
        if (!fields[0].equals("."))
            builder.addRDN(BCStyle.CN, fields[0]);


        System.out.print("Organization (O): ");
        fields[1] = input.nextLine();
        if (!fields[1].equals("."))
            builder.addRDN(BCStyle.O, fields[1]);


        System.out.print("Organizational Unit (OU): ");
        fields[2] = input.nextLine();
        if (!fields[2].equals("."))
            builder.addRDN(BCStyle.OU, fields[2]);


        System.out.print("City/Locality (L): ");
        fields[3] = input.nextLine();
        if (!fields[3].equals("."))
            builder.addRDN(BCStyle.L, fields[3]);


        System.out.print("Country (C): ");
        fields[4] = input.nextLine();
        if (!fields[4].equals("."))
            builder.addRDN(BCStyle.C, fields[4]);


        System.out.print("Email Address: ");
        fields[5] = input.nextLine();
        if (!fields[5].equals("."))
            builder.addRDN(BCStyle.CN, fields[5]);


        return builder.build();
    }


    private ContentSigner prepareSigner(String signatureAlgorithm, KeyPair keyPair) {

        //create signer
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = null;
        try {
            signer = signerBuilder.build(keyPair.getPrivate());
            return signer;
        } catch (OperatorCreationException e) {
            e.printStackTrace();
            return null;
        }

    }


}
