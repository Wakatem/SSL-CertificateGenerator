import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
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

        try {
            showConsole();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

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

        CertificateGenerator certificateGenerator = new CertificateGenerator();
        CSRGenerator csrGenerator = new CSRGenerator();
        switch (choice) {
            case 1: {
                X509Certificate certificate = certificateGenerator.generateSelfSignedCert("RSA", 2048, new SecureRandom(), "SHA256WithRSA", 365);
                certificateGenerator.exportCertificate(certificate, new File("."), "new certificate");
                break;
            }

            case 2: {
                scanner = new Scanner(System.in);
                String pathInput;


                //fetching the CSR
                System.out.print("\n\nEnter CSR filepath: ");
                pathInput = scanner.nextLine();
                File csrPath = new File(pathInput);
                PKCS10CertificationRequest CSR = csrGenerator.importCSR(csrPath);

                //fetching the issuer certificate
                System.out.print("\n\nEnter issuer certificate filepath: ");
                pathInput = scanner.nextLine();
                File issuerCertificatePath = new File(pathInput);
                X509Certificate issuerCertificate = null;
                try {
                    CertificateFactory factory = CertificateFactory.getInstance("X509");
                    issuerCertificate = (X509Certificate) factory.generateCertificate(new FileInputStream(issuerCertificatePath));

                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }


                //fetching issuer private key
                System.out.print("\n\nEnter issuer private key filepath: ");
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

                X500Name issuer = new X500Name(issuerCertificate.getSubjectX500Principal().toString());
                X509Certificate subjectCertificate = certificateGenerator.generateSignedCertificate(CSR, "SHA256WithRSA", new SecureRandom(), issuer, privateKey, 365);
                certificateGenerator.exportCertificate(subjectCertificate, new File("."), "new certificate");
                break;
            }

            case 3: {
                PKCS10CertificationRequest CSR = csrGenerator.generateCSR("RSA", 2048, new SecureRandom(), "SHA256WithRSA");
                csrGenerator.exportCSR(CSR, new File("."), "new CSR");
                break;
            }

            case 4:
                scanner = new Scanner(System.in);
                String pathInput;

                //fetching the subject certificate
                System.out.print("\n\nEnter subject certificate filepath: ");
                pathInput = scanner.nextLine();
                File subjectCertificatePath = new File(pathInput);
                X509Certificate subjectCertificate = null;
                try {
                    CertificateFactory factory = CertificateFactory.getInstance("X509");
                    subjectCertificate = (X509Certificate) factory.generateCertificate(new FileInputStream(subjectCertificatePath));

                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }

                System.out.print("\n\n1. Validate using extracted public key from a certificate");
                System.out.print("\n2. Validate using given public key");
                System.out.print("\n--> ");
                choice = scanner.nextInt();

                if (choice == 1) {

                    //fetching the issuer certificate
                    System.out.print("\n\nEnter issuer certificate filepath: ");
                    pathInput = scanner.next();
                    File issuerCertificatePath = new File(pathInput);
                    X509Certificate issuerCertificate = null;
                    PublicKey publicKey = null;
                    try {
                        CertificateFactory factory = CertificateFactory.getInstance("X509");
                        issuerCertificate = (X509Certificate) factory.generateCertificate(new FileInputStream(issuerCertificatePath));
                        publicKey = issuerCertificate.getPublicKey();
                    } catch (CertificateException e) {
                        e.printStackTrace();
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }


                    boolean verified = certificateGenerator.CertificateIsVerified(subjectCertificate, publicKey);
                    if (verified)
                        System.out.println("certificate is verified");

                } else if (choice == 2) {

                    //fetching the issuer public key
                    System.out.print("\n\nEnter issuer public key: ");
                    pathInput = scanner.next();
                    File publicKeyPath = new File(pathInput);
                    PublicKey publicKey = null;
                    try {
                        FileInputStream fis = new FileInputStream(publicKeyPath);
                        publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(fis.readAllBytes()));

                    } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    boolean verified = certificateGenerator.CertificateIsVerified(subjectCertificate, publicKey);
                    if (verified)
                        System.out.println("certificate is verified");

                } else {
                    System.out.println("wrong input");
                }

                break;

            case 5: {

                //fetching the CSR
                System.out.print("\n\nEnter CSR filepath: ");
                pathInput = scanner.nextLine();
                File csrPath = new File(pathInput);
                PKCS10CertificationRequest request = csrGenerator.importCSR(csrPath);

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

            default:
                System.out.println("wrong input");
                break;

        }


        System.out.println("enter any character to exit...");
        scanner.nextLine();

    }


    public static void showConsole() throws IOException, URISyntaxException {

        //if current process has no window
        if (System.console() == null) {

            String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            String jarName = jarPath.substring(jarPath.lastIndexOf("/")+1);

            Runtime.getRuntime().exec("cmd /c start java -jar "+jarName);

            return; //System.exit();   or   return; to terminate current console-less process
        }

    }

}
