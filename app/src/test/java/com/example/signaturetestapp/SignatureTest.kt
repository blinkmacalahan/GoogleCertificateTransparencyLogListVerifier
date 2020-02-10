package com.example.signaturetestapp

import android.content.Context
import android.os.Build.VERSION_CODES
import androidx.test.core.app.ApplicationProvider
import org.junit.*
import org.junit.runner.*
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SignatureException
import java.security.spec.InvalidKeySpecException

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [VERSION_CODES.O_MR1])
class SignatureTest {

    private lateinit var signatureBytes: ByteArray

    private lateinit var keyBytes: ByteArray

    private lateinit var jsonBytes: ByteArray

    /**
     * Unable to use @BeforeClass due to context not being available yet:
     * java.lang.IllegalStateException: No instrumentation registered! Must run under a registering instrumentation.
     */
    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        try {
            signatureBytes = MainJavaActivity.toByteArray(context.assets.open("log_list.sig"))
            keyBytes = MainJavaActivity.loadPEM(context.assets.open("log_list_pubkey.pem"))
            jsonBytes = MainJavaActivity.toByteArray(context.assets.open("log_list.json"))
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    @Test
    @Throws(
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        InvalidKeyException::class,
        SignatureException::class
    )
    fun verifyLogListWithUppercase() {
        Assert.assertTrue(
            "Verify with " + MainJavaActivity.UPPERCASE_WITH_SHA256_WITH_RSA,
            MainJavaActivity.isGoogleLogListVerified(
                MainJavaActivity.UPPERCASE_WITH_SHA256_WITH_RSA,
                signatureBytes,
                keyBytes,
                jsonBytes
            )
        )
    }

    @Test
    @Throws(
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        InvalidKeyException::class,
        SignatureException::class
    )
    fun verifyLogListWithLowercase() {
        Assert.assertTrue(
            "Verify with " + MainJavaActivity.LOWERCASE_SHA256_WITH_RSA,
            MainJavaActivity.isGoogleLogListVerified(
                MainJavaActivity.LOWERCASE_SHA256_WITH_RSA,
                signatureBytes,
                keyBytes,
                jsonBytes
            )
        )
    }
}
