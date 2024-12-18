package inc.whew.android.fakegapps;

import android.annotation.TargetApi;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.util.ArraySet;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.PublicKey;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class FakeSignatures implements IXposedHookLoadPackage {
    private static final String TAG = "FakeGApps";
    private static final String _x509cert = "MIIEQzCCAyugAwIBAgIJAMLgh0ZkSjCNMA0GCSqGSIb3DQEBBAUAMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDAeFw0wODA4MjEyMzEzMzRaFw0zNjAxMDcyMzEzMzRaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDCCASAwDQYJKoZIhvcNAQEBBQADggENADCCAQgCggEBAKtWLgDYO6IIrgqWbxJOKdoR8qtW0I9Y4sypEwPpt1TTcvZApxsdyxMJZ2JORland2qSGT2y5b+3JKkedxiLDmpHpDsz2WCbdxgxRczfey5YZnTJ4VZbH0xqWVW/8lGmPav5xVwnIiJS6HXk+BVKZF+JcWjAsb/GEuq/eFdpuzSqeYTcfi6idkyugwfYwXFU1+5fZKUaRKYCwkkFQVfcAs1fXA5V+++FGfvjJ/CxURaSxaBvGdGDhfXE28LWuT9ozCl5xw4Yq5OGazvV24mZVSoOO0yZ31j7kYvtwYK6NeADwbSxDdJEqO4k//0zOHKrUiGYXtqw/A0LFFtqoZKFjnkCAQOjgdkwgdYwHQYDVR0OBBYEFMd9jMIhF1Ylmn/Tgt9r45jk14alMIGmBgNVHSMEgZ4wgZuAFMd9jMIhF1Ylmn/Tgt9r45jk14aloXikdjB0MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEUMBIGA1UEChMLR29vZ2xlIEluYy4xEDAOBgNVBAsTB0FuZHJvaWQxEDAOBgNVBAMTB0FuZHJvaWSCCQDC4IdGZEowjTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBAUAA4IBAQBt0lLO74UwLDYKqs6Tm8/yzKkEu116FmH4rkaymUIE0P9KaMftGlMexFlaYjzmB2OxZyl6euNXEsQH8gjwyxCUKRJNexBiGcCEyj6z+a1fuHHvkiaai+KL8W1EyNmgjmyy8AW7P+LLlkR+ho5zEHatRbM/YAnqGcFh5iZBqpknHf1SKMXFh4dd239FJ1jWYfbMDMy3NS5CTMQ2XFI1MvcyUTdZPErjQfTbQe3aDQsQcafEQPD+nqActifKZ0Np0IS9L9kR/wbNvyz6ENwPiTrjV2KRkEjH78ZMcUQXg0L3BYHJ3lc69Vs5Ddf9uUGGMYldX3WfMBEmh/9iFBDAaTCK";

    @Override
    public void handleLoadPackage(LoadPackageParam loadedPackage) throws CertificateException {
        if (!loadedPackage.packageName.equals("android"))
            return;

        final byte[] certBytes = Base64.decode(_x509cert, Base64.DEFAULT);
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        final Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                PackageInfo pi = (PackageInfo) param.getResult();
                if (pi != null) {
                    String packageName = pi.packageName;
                    if (packageName.equals("com.google.android.gms") || packageName.equals("com.android.vending")) {
                        pi.signatures = new Signature[]{new Signature(certBytes)};

                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                            SigningInfo signingInfo = createSigningInfo(new Signature(certBytes), cert.getPublicKey());
                            if (signingInfo != null) {
                                pi.signingInfo = signingInfo;
                            }
                        }

                        param.setResult(pi);
                    }
                }
            }
        };

        String classToHook;
        switch (Build.VERSION.SDK_INT) {
            case Build.VERSION_CODES.BASE: // SDK 1
            case Build.VERSION_CODES.BASE_1_1: // SDK 2
            case Build.VERSION_CODES.CUPCAKE: // SDK 3
            case Build.VERSION_CODES.DONUT: // SDK 4
            case Build.VERSION_CODES.ECLAIR: // SDK 5
            case Build.VERSION_CODES.ECLAIR_0_1: // SDK 6
            case Build.VERSION_CODES.ECLAIR_MR1: // SDK 7
            case Build.VERSION_CODES.FROYO: // SDK 8
            case Build.VERSION_CODES.GINGERBREAD: // SDK 9
            case Build.VERSION_CODES.GINGERBREAD_MR1: // SDK 10
            case Build.VERSION_CODES.HONEYCOMB: // SDK 11
            case Build.VERSION_CODES.HONEYCOMB_MR1: // SDK 12
            case Build.VERSION_CODES.HONEYCOMB_MR2: // SDK 13
            case Build.VERSION_CODES.ICE_CREAM_SANDWICH: // SDK 14
            case Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1: // SDK 15
            case Build.VERSION_CODES.JELLY_BEAN: // SDK 16
            case Build.VERSION_CODES.JELLY_BEAN_MR1: // SDK 17
            case Build.VERSION_CODES.JELLY_BEAN_MR2: // SDK 18
            case Build.VERSION_CODES.KITKAT: // SDK 19
            case Build.VERSION_CODES.KITKAT_WATCH: // SDK 20
            case Build.VERSION_CODES.LOLLIPOP: // SDK 21
            case Build.VERSION_CODES.LOLLIPOP_MR1: // SDK 22
            case Build.VERSION_CODES.M: // SDK 23
            case Build.VERSION_CODES.N: // SDK 24
            case Build.VERSION_CODES.N_MR1: // SDK 25
            case Build.VERSION_CODES.O: // SDK 26
            case Build.VERSION_CODES.O_MR1: // SDK 27
            case Build.VERSION_CODES.P: // SDK 28
            case Build.VERSION_CODES.Q: // SDK 29
            case Build.VERSION_CODES.R: // SDK 30
                classToHook = "com.android.server.pm.PackageManagerService";
                break;
            case Build.VERSION_CODES.S: // SDK 31
            case Build.VERSION_CODES.S_V2: // SDK 32
                classToHook = "com.android.server.pm.PackageManagerService.ComputerEngine";
                break;
            case Build.VERSION_CODES.TIRAMISU: // SDK 33
            case Build.VERSION_CODES.UPSIDE_DOWN_CAKE: // SDK 34
            default:
                classToHook = "com.android.server.pm.ComputerEngine";
                break;
        }

        final Class<?> hookedClass = XposedHelpers.findClass(classToHook, loadedPackage.classLoader);
        XposedBridge.hookAllMethods(hookedClass, "generatePackageInfo", hook);
    }

    private static Class<?> findFirstLoadableClass(String... candidates) throws ClassNotFoundException {
        ClassNotFoundException exc = new ClassNotFoundException();
        for (String candidate : candidates) {
            try {
                return Class.forName(candidate);
            } catch (ClassNotFoundException e) {
                exc = e;
            }
        }
        throw exc;
    }

    @TargetApi(android.os.Build.VERSION_CODES.P)
    private SigningInfo createSigningInfo(Signature sig, PublicKey publicKey) {
        final int SIGNING_BLOCK_V3 = 3;
        final Signature[] sigs = new Signature[]{sig};
        final ArraySet<PublicKey> pks = new ArraySet<>();
        pks.add(publicKey);

        // Unfortunately, SigningDetails is not exported in SDK, so we have to rely on reflection.
        // Also, public SigningInfo constructor is only available from API 35, so we can't use it.
        try {
            Class<?> signingDetailsClass = findFirstLoadableClass(
                "android.content.pm.SigningDetails",
                // Android 9 to 12 have SigningDetails embedded in the PackageParser class
                "android.content.pm.PackageParser$SigningDetails"
            );
            // https://cs.android.com/android/platform/superproject/+/1c19b376095446666df2b2d9290dac3ef71da846:frameworks/base/core/java/android/content/pm/SigningDetails.java;l=146
            Constructor<?> signingDetailsConstructor = signingDetailsClass.getDeclaredConstructor(
                Signature[].class, // signatures
                int.class, // signatureSchemeVersion
                ArraySet.class, // keys
                Signature[].class // pastSigningCertificates
            );
            Constructor<SigningInfo> signingInfoConstructor = SigningInfo.class.getDeclaredConstructor(signingDetailsClass);

            signingDetailsConstructor.setAccessible(true);
            signingInfoConstructor.setAccessible(true);

            Object signingDetails = signingDetailsConstructor.newInstance(sigs, SIGNING_BLOCK_V3, pks, null);
            return signingInfoConstructor.newInstance(signingDetails);
        } catch (Exception e) {
            XposedBridge.log(String.format("%s failed to create signingInfo", TAG));
            XposedBridge.log(e);
        }

        return null;
    }
}
