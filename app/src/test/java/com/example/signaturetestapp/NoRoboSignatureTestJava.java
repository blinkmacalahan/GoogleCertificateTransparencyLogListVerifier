package com.example.signaturetestapp;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import org.junit.*;

public class NoRoboSignatureTestJava {
    private static byte[] sSignatureBytes;

    private static byte[] sKeyBytes;

    private static byte[] sJsonBytes;

    /**
     * Unable to use @BeforeClass due to context not being available yet:
     * java.lang.IllegalStateException: No instrumentation registered! Must run under a registering instrumentation.
     */
    @Before
    public void setup() {
        try {
            sSignatureBytes = MainJavaActivity.toByteArray(getClass().getResourceAsStream("log_list.sig"));
            sKeyBytes = MainJavaActivity.loadPEM(getClass().getResourceAsStream("log_list_pubkey.pem"));
            sJsonBytes = MainJavaActivity.toByteArray(getClass().getResourceAsStream("log_list.json"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Test
    public void verifyLogListWithUppercase() throws InvalidKeySpecException, NoSuchAlgorithmException,
            InvalidKeyException,
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
