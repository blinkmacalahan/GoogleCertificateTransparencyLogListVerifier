package com.example.signaturetestapp;

import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import org.junit.*;


public class AndroidSignatureTestJava {

    private static byte[] sSignatureBytes;

    private static byte[] sKeyBytes;

    private static byte[] sJsonBytes;

    @BeforeClass
    public static void setup() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        try {
            sSignatureBytes = MainJavaActivity.toByteArray(context.getAssets().open("log_list.sig"));
            sKeyBytes = MainJavaActivity.loadPEM(context.getAssets().open("log_list_pubkey.pem"));
            sJsonBytes = MainJavaActivity.toByteArray(context.getAssets().open("log_list.json"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Test
    public void verifyLogListWithUppercase() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {

        Assert.assertTrue("Verify with " + MainJavaActivity.UPPERCASE_WITH_SHA256_WITH_RSA,
                MainJavaActivity.isGoogleLogListVerified(MainJavaActivity.UPPERCASE_WITH_SHA256_WITH_RSA,
                        sSignatureBytes,
                        sKeyBytes,
                        sJsonBytes));
    }

    @Test
    public void verifyLogListWithLowercase() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        Assert.assertTrue("Verify with " + MainJavaActivity.LOWERCASE_SHA256_WITH_RSA,
                MainJavaActivity.isGoogleLogListVerified(MainJavaActivity.LOWERCASE_SHA256_WITH_RSA,
                        sSignatureBytes,
                        sKeyBytes,
                        sJsonBytes));
    }
}
