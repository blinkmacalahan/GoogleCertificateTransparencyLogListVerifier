package com.example.signaturetestapp

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.example.signaturetestapp.R.id
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.regex.Pattern

class MainActivity : AppCompatActivity(), View.OnClickListener {

    companion object {
        fun loadPEMFile(inputStream: InputStream): ByteArray {
            val pubBytes = toByteArray(inputStream)
            val pem = String(pubBytes)
            val parse = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*")
            val encoded = parse.matcher(pem).replaceFirst("$1")
            return Base64.getMimeDecoder().decode(encoded)
        }

        fun toByteArray(inputStream: InputStream): ByteArray {
            val outputStream = ByteArrayOutputStream()
            val buffer = ByteArray(1024)

            var len: Int
            do {
                len = inputStream.read(buffer)
                if (len != -1) {
                    outputStream.write(buffer, 0, len)
                }
            } while (len != -1)

            return outputStream.toByteArray()
        }

        fun isGoogleLogListVerified(context: Context): Boolean {
            val sigBytes = toByteArray(context.assets.open("log_list.sig"))
            val publicKeyBytes = loadPEMFile(context.assets.open("log_list_pubkey.pem"))
            val jsonBytes = toByteArray(context.assets.open("log_list.json"))
            val keyFactory = KeyFactory.getInstance("RSA")
            val signature = Signature.getInstance("SHA256withRSA").apply {
                initVerify(keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes)))
                update(jsonBytes)
            }
            val isVerified = signature.verify(sigBytes)
            Log.d(MainJavaActivity.TAG, "isSignatureVerified: $isVerified")
            return isVerified
        }
    }

    private lateinit var textView: TextView
    private lateinit var uppercaseAlgorithm: Button
    private lateinit var lowercaseAlgorithm: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        textView = findViewById(id.text)
        uppercaseAlgorithm = findViewById(id.uppercase)
        lowercaseAlgorithm = findViewById(id.lowercase)

        uppercaseAlgorithm.setOnClickListener(this)
        lowercaseAlgorithm.setOnClickListener(this)
    }

    override fun onClick(v: View?) {
        if (v === uppercaseAlgorithm) {
            verifyLogList(MainJavaActivity.UPPERCASE_WITH_SHA256_WITH_RSA)
        } else if (v === lowercaseAlgorithm) {
            verifyLogList(MainJavaActivity.LOWERCASE_SHA256_WITH_RSA)
        }
    }

    private fun onVerificationComplete(displayText: String) {
        textView.text = displayText
    }

    private fun verifyLogList(algorithm: String) {
        try {
            val result = isGoogleLogListVerified(applicationContext)
            textView.post {
                onVerificationComplete(if (result) "$algorithm: Log List is Verified" else "$algorithm: Log list FAILED verification")
            }
        } catch (e: Exception) {
            textView.post {
                onVerificationComplete(
                    algorithm + ": Error while verifying log list.\n" + e.message
                )
            }
            e.printStackTrace()
        }
    }

    // JAVA 8 Version that does the same thing
//    public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException {
//        FileInputStream fis = new FileInputStream(INSERT_FILE_PATH_TO_log_list.sig);
//        byte[] sigBytes = toByteArray(fis);
////		System.out.println(sigBytes.length);
//        byte[] pubBytes = loadPEM(INSERT_FILE_PATH_TO_log_list_pubkey.pem);
//        byte[] json = toByteArray(new FileInputStream(INSERT_FILE_PATH_TO_log_list.json));
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        Signature sig = Signature.getInstance("SHA256withRSA");
//        System.out.println(kf.generatePublic(new X509EncodedKeySpec(pubBytes)));
//        sig.initVerify(kf.generatePublic(new X509EncodedKeySpec(pubBytes)));
//        sig.update(json);
//        System.out.println(sig.verify(sigBytes));
//    }
//    public static byte[] toByteArray(InputStream in) throws IOException {
//        ByteArrayOutputStream os = new ByteArrayOutputStream();
//        byte[] buffer = new byte[1024];
//        int len;
//        // read bytes from the input stream and store them in buffer
//        while ((len = in.read(buffer)) != -1) {
//            // write bytes from the buffer into output stream
//            os.write(buffer, 0, len);
//        }
//        return os.toByteArray();
//    }
//    private static byte[] loadPEM(String resource) throws IOException {
//        byte[] pubBytes = toByteArray(new FileInputStream(resource));
//        String pem = new String(pubBytes);
//        Pattern parse = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
//        String encoded = parse.matcher(pem).replaceFirst("$1");
//        return Base64.getMimeDecoder().decode(encoded);
//    }
}
