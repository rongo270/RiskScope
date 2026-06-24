package com.rongo.riskscope.network

import com.rongo.riskscope.model.ServerVerdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Talks to RiskScope-Server. Stateless w.r.t. the base URL (which the user can
 * change in Settings) — each call is given the current base URL and the Retrofit
 * instance is cached per URL.
 */
class HashCheckRepository {

    private val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
    }

    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)   // Render free tier can cold-start ~50s
            .writeTimeout(30, TimeUnit.SECONDS)
            .callTimeout(90, TimeUnit.SECONDS)
            .addInterceptor(HttpLoggingInterceptor().apply {
                level = HttpLoggingInterceptor.Level.BASIC
            })
            .build()
    }

    private var cachedBaseUrl: String? = null
    private var cachedApi: RiskScopeApi? = null

    private fun api(rawBaseUrl: String): RiskScopeApi {
        val base = normalizeBaseUrl(rawBaseUrl)
        cachedApi?.let { if (cachedBaseUrl == base) return it }
        val contentType = "application/json".toMediaType()
        val api = Retrofit.Builder()
            .baseUrl(base)
            .client(httpClient)
            .addConverterFactory(json.asConverterFactory(contentType))
            .build()
            .create(RiskScopeApi::class.java)
        cachedBaseUrl = base
        cachedApi = api
        return api
    }

    /**
     * Checks every hash and returns a map keyed by lowercase hash. A hash present
     * in the map was checked by the server (malicious OR clean); absent means it
     * was not part of any successful response.
     */
    suspend fun batchCheck(baseUrl: String, hashes: List<String>): Map<String, ServerVerdict> =
        withContext(Dispatchers.IO) {
            val distinct = hashes.filter { it.isNotBlank() }.map { it.lowercase() }.distinct()
            if (distinct.isEmpty()) return@withContext emptyMap()
            val service = api(baseUrl)
            val out = HashMap<String, ServerVerdict>(distinct.size)
            for (chunk in distinct.chunked(MAX_BATCH)) {
                val response = service.checkBatch(BatchRequest(chunk))
                for (dto in response.results) {
                    val key = (dto.hash ?: continue).lowercase()
                    out[key] = dto.toDomain()
                }
            }
            out
        }

    suspend fun fetchStats(baseUrl: String): StatsDto =
        withContext(Dispatchers.IO) { api(baseUrl).stats() }

    private fun HashVerdictDto.toDomain() = ServerVerdict(
        isMalicious = isMalicious,
        matchType = matchType,
        source = source,
        sources = sources,
        signature = signature,
        fileType = fileType,
        explanation = explanation,
    )

    companion object {
        const val MAX_BATCH = 500

        /** Ensure a usable, trailing-slash base URL; default to https when no scheme. */
        fun normalizeBaseUrl(raw: String): String {
            var url = raw.trim()
            if (url.isEmpty()) return url
            if (!url.startsWith("http://") && !url.startsWith("https://")) url = "https://$url"
            if (!url.endsWith("/")) url += "/"
            return url
        }
    }
}
