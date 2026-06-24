package com.rongo.riskscope.network

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

interface RiskScopeApi {

    @POST("api/check/batch")
    suspend fun checkBatch(@Body body: BatchRequest): BatchResponse

    @POST("api/check")
    suspend fun check(@Body body: Map<String, String>): HashVerdictDto

    @GET("api/stats")
    suspend fun stats(): StatsDto
}
