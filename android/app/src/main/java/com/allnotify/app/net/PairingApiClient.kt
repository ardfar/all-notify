package com.allnotify.app.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

@Serializable
data class ClaimCodeRequest(
    val code: String,
    val platform: String = "android"
)

@Serializable
data class ClaimCodeResponse(
    @SerialName("device_id") val deviceId: String,
    val token: String,
    val name: String,
    val platform: String,
    @SerialName("can_add_devices") val canAddDevices: Boolean = false
)

@Serializable
data class DeviceMeResponse(
    @SerialName("device_id") val deviceId: String,
    val name: String,
    val platform: String,
    @SerialName("can_add_devices") val canAddDevices: Boolean = false
)

@Serializable
data class CreatePairingCodeRequest(
    val name: String,
    val platform: String
)

@Serializable
data class CreatedPairingCodeResponse(
    @SerialName("code_id") val codeId: String,
    val code: String,
    val name: String,
    val platform: String,
    @SerialName("can_add_devices") val canAddDevices: Boolean = false,
    @SerialName("expires_at") val expiresAt: Long
)

@Serializable
data class PairingCodeSummary(
    @SerialName("code_id") val codeId: String,
    val name: String,
    val platform: String,
    @SerialName("can_add_devices") val canAddDevices: Boolean = false,
    val status: String,
    @SerialName("claimed_device_id") val claimedDeviceId: String? = null,
    @SerialName("created_at") val createdAt: Long = 0L,
    @SerialName("expires_at") val expiresAt: Long
)

@Serializable
private data class ApiErrorEnvelope(
    val error: ApiErrorBody? = null
)

@Serializable
private data class ApiErrorBody(
    val code: String = "",
    val message: String = ""
)

class PairingApiException(
    val httpStatus: Int,
    val errorCode: String,
    override val message: String
) : IOException(message)

class PairingApiClient(private val httpClient: OkHttpClient) {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    suspend fun claimCode(
        serverUrl: String,
        code: String,
        platform: String = "android"
    ): ClaimCodeResponse = withContext(Dispatchers.IO) {
        val bodyStr = json.encodeToString(ClaimCodeRequest(code = code, platform = platform))
        val req = Request.Builder()
            .url("${serverUrl.trimEnd('/')}/v1/pair/claim")
            .post(bodyStr.toRequestBody(JSON_MEDIA_TYPE))
            .build()
        httpClient.newCall(req).execute().use { resp ->
            val raw = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw parseApiError(resp.code, raw)
            }
            json.decodeFromString<ClaimCodeResponse>(raw)
        }
    }

    suspend fun fetchMe(serverUrl: String, token: String): DeviceMeResponse = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url("${serverUrl.trimEnd('/')}/v1/me")
            .header("Authorization", "Bearer $token")
            .get()
            .build()
        httpClient.newCall(req).execute().use { resp ->
            val raw = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw parseApiError(resp.code, raw)
            }
            json.decodeFromString<DeviceMeResponse>(raw)
        }
    }

    suspend fun createPairingCode(
        serverUrl: String,
        token: String,
        name: String,
        platform: String
    ): CreatedPairingCodeResponse = withContext(Dispatchers.IO) {
        val bodyStr = json.encodeToString(CreatePairingCodeRequest(name = name, platform = platform))
        val req = Request.Builder()
            .url("${serverUrl.trimEnd('/')}/v1/pairing-codes")
            .header("Authorization", "Bearer $token")
            .post(bodyStr.toRequestBody(JSON_MEDIA_TYPE))
            .build()
        httpClient.newCall(req).execute().use { resp ->
            val raw = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw parseApiError(resp.code, raw)
            }
            json.decodeFromString<CreatedPairingCodeResponse>(raw)
        }
    }

    suspend fun listPairingCodes(serverUrl: String, token: String): List<PairingCodeSummary> =
        withContext(Dispatchers.IO) {
            val req = Request.Builder()
                .url("${serverUrl.trimEnd('/')}/v1/pairing-codes")
                .header("Authorization", "Bearer $token")
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                val raw = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) {
                    throw parseApiError(resp.code, raw)
                }
                json.decodeFromString<List<PairingCodeSummary>>(raw)
            }
        }

    private fun parseApiError(httpStatus: Int, rawBody: String): PairingApiException {
        val parsed = runCatching { json.decodeFromString<ApiErrorEnvelope>(rawBody) }.getOrNull()?.error
        val code = parsed?.code?.takeIf { it.isNotBlank() } ?: "HTTP_$httpStatus"
        val msg = when {
            httpStatus == 404 || httpStatus == 410 || code == "CODE_NOT_FOUND" || code == "CODE_EXPIRED_OR_USED" ->
                "This pairing code expired or was already used — create a new one."
            !parsed?.message.isNullOrBlank() -> parsed!!.message
            else -> "Request failed (HTTP $httpStatus)"
        }
        return PairingApiException(httpStatus, code, msg)
    }

    companion object {
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }
}
