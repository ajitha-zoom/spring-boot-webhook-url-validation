package com.example.demo

import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@SpringBootApplication
class DemoApplication

fun main(args: Array<String>) {
    runApplication<DemoApplication>(*args)
}

@RestController
class MessageController {
    @GetMapping("/")
    fun index(@RequestParam("name") name: String) = "Hello, $name!"
}

data class ZoomWebhookRequest(
    val payload: Payload,
    val event_ts: Long,
    val event: String
)

data class Payload(
    val plainToken: String
)

data class ZoomWebhookMessage(
    val plainToken: String,
    val encryptedToken: String
)

@RestController
class ZoomWebhookController {

    private val logger: Logger = LoggerFactory.getLogger(ZoomWebhookController::class.java)

    @PostMapping("/webhook")
    fun handleZoomWebhook(
            @RequestHeader("x-zm-request-timestamp") requestTimestamp: String,
            @RequestHeader("x-zm-signature") requestSignature: String,
            @RequestBody requestBody: ZoomWebhookRequest
    ): ResponseEntity<Any> {

        logger.debug("ajitha ");
        val secretToken = "XXX";

        // Construct the message string
        val message = "v0:$requestTimestamp:${ObjectMapper().writeValueAsString(requestBody)}"

        // Log request data
        logger.info("Received request:")
        logger.info("Request Signature: $requestSignature")

        // Create HMAC SHA-256 hash
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(secretToken.toByteArray(), "HmacSHA256")
        mac.init(secretKey)
        val hashForVerify = mac.doFinal(message.toByteArray(StandardCharsets.UTF_8))
        val hexHashForVerify = bytesToHex(hashForVerify)

        logger.info("Expected Signature: v0=$hexHashForVerify")

        if (requestSignature == "v0=$hexHashForVerify") {
            logger.info("Request is valid.")

            // Zoom is validating the webhook endpoint
            if (requestBody.event == "endpoint.url_validation") {
                val plainToken = requestBody.payload.plainToken

                // Recreate the hash for validation
                val hashForValidate = mac.doFinal(plainToken.toByteArray(StandardCharsets.UTF_8))
                val hexHashForValidate = bytesToHex(hashForValidate)

                // Construct a JSON response
                val response = ZoomWebhookMessage(plainToken = plainToken, encryptedToken = hexHashForValidate)
                //logger.info("Response: $response")
                return ResponseEntity.ok(response)
            }
        }
        logger.warn("Invalid request.")

        // Handle invalid requests
        return ResponseEntity.status(400).body("Invalid request")
    }

    // Function to convert bytes to a hexadecimal string
    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = "0123456789abcdef"[v ushr 4]
            hexChars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
        }
        return String(hexChars)
    }
}