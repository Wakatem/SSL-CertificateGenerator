import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

        System.out.println("SSLCertificateGenerator\n======================\n");
        System.out.println("1. Generate self-signed certificate");
        System.out.println("2. Generate signed certificate");
        System.out.println("3. Generate CSR");
        System.out.println("4. Verify Certificate");
        System.out.println("5. Verify CSR");


        Scanner scanner = new Scanner(System.in);
        int choice;
        System.out.print("--> ");
        choice = scanner.nextInt();

        switch (choice) {
            case 1: {
                CertificateGenerator generator = new CertificateGenerator();
                X509Certificate certificate = generator.generateSelfSignedCert("RSA", 2048, new SecureRandom(), "SHA256WithRSA", 365);
                generator.exportCertificate(certificate, new File("."), "test");
                break;
            }

            case 2: {
                scanner = new Scanner(System.in);
                String pathInput;
                CSRGenerator csrGenerator = new CSRGenerator();
                CertificateGenerator certificateGenerator = new CertificateGenerator();


                //fetching the CSR
                System.out.print("\n\nEnter CSR filepath: ");
                pathInput = scanner.nextLine();
                File csrPath = new File(pathInput);
                PKCS10CertificationRequest CSR = csrGenerator.importCSR(csrPath);

                //fetching the CA certificate
                System.out.print("\n\nEnter CA certificate filepath: ");
                pathInput = scanner.nextLine();
                File caCertificatePath = new File(pathInput);
                X509Certificate CACertificate = null;
                try {
                    CertificateFactory factory = CertificateFactory.getInstance("X509");
                    CACertificate = (X509Certificate) factory.generateCertificate(new FileInputStream(caCertificatePath));

                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }


                //fetching CA private key
                System.out.print("\n\nEnter CA private key filepath: ");
                pathInput = scanner.nextLine();
                File privateKeyPath = new File(pathInput);
                PrivateKey privateKey = null;
                try {
                    FileInputStream fis = new FileInputStream(privateKeyPath);
                    privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(fis.readAllBytes()));
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                X500Name issuer = new X500Name(CACertificate.getSubjectX500Principal().toString());
                X509Certificate subjectCertificate = certificateGenerator.generateSignedCertificate(CSR, "SHA256WithRSA", new SecureRandom(), issuer, privateKey, 365);
                certificateGenerator.exportCertificate(subjectCertificate, new File("."), "finally");
                break;
            }

            case 3: {
                CSRGenerator csrGenerator = new CSRGenerator();
                PKCS10CertificationRequest CSR = csrGenerator.generateCSR("RSA", 2048, new SecureRandom(), "SHA256WithRSA");
                csrGenerator.exportCSR(CSR, new File("."), "testCSR");
                break;
            }
            case 4:
                break;
            case 5: {
                CSRGenerator csrGenerator = new CSRGenerator();
                PKCS10CertificationRequest request = csrGenerator.importCSR(new File("testCSR.csr"));
                try {
                    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getSubjectPublicKeyInfo().getEncoded()));
                    boolean verified = csrGenerator.CSRisVerified(request, publicKey);
                    if (verified)
                        System.out.println("valid CSR");

                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                break;
            }

        }


    }


}
