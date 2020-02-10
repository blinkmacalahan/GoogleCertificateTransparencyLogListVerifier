package com.example.signaturetestapp

import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.*
import java.io.IOException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SignatureException
import java.security.spec.InvalidKeySpecException

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4ClassRunner::class)
class AndroidSignatureTest {

    companion object {
        private lateinit var signatureBytes: ByteArray

        private lateinit var keyBytes: ByteArray

        private lateinit var jsonBytes: ByteArray

        @BeforeClass @JvmStatic
        fun setup() {
            val context =
                InstrumentationRegistry.getInstrumentation().targetContext
            try {
                signatureBytes = MainJavaActivity.toByteArray(context.assets.open("log_list.sig"))
                keyBytes = MainJavaActivity.loadPEM(context.assets.open("log_list_pubkey.pem"))
                jsonBytes = MainJavaActivity.toByteArray(context.assets.open("log_list.json"))
            } catch (e: IOException) {
                e.printStackTrace()
            }
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
        assertTrue(
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
        assertTrue(
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
