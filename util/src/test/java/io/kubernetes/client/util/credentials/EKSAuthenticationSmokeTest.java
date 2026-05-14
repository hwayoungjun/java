/*
Copyright 2026 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package io.kubernetes.client.util.credentials;

import static org.assertj.core.api.Assertions.assertThat;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.auth.ApiKeyAuth;
import io.kubernetes.client.util.ClientBuilder;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import okhttp3.Interceptor;
import okhttp3.Request;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.eks.EksClient;
import software.amazon.awssdk.services.eks.model.Cluster;

class EKSAuthenticationSmokeTest {
    private static final String AWS_CREDENTIAL_PROFILE_NAME = "";
    private static final String AWS_REGION = "";
    private static final String AWS_EKS_CLUSTER_NAME = "";
    private static final int EXPIRY_SECONDS = 60;

    private static final AwsCredentialsProvider provider = ProfileCredentialsProvider.create(
        AWS_CREDENTIAL_PROFILE_NAME);

    private static Cluster cluster;
    private static EksClient eksClient;

    @BeforeAll
    static void setUp() {
        if (AWS_EKS_CLUSTER_NAME == null || AWS_EKS_CLUSTER_NAME.isBlank()) {
            throw new IllegalStateException("Set -Deks.smoke.clusterName=<cluster-name> to run this smoke test.");
        }

        eksClient = EksClient.builder()
            .region(Region.of(AWS_REGION))
            .credentialsProvider(provider)
            .httpClientBuilder(UrlConnectionHttpClient.builder())
            .build();
        cluster = eksClient.describeCluster(request -> request.name(AWS_EKS_CLUSTER_NAME)).cluster();
    }

    @AfterAll
    static void cleanUp() {
        if (eksClient != null) {
            eksClient.close();
        }
    }

    @Test
    void original_eks_authentication_test() throws IOException {
        ApiClient client = ClientBuilder.standard()
            .setBasePath(cluster.endpoint())
            .setCertificateAuthority(Base64.getDecoder().decode(cluster.certificateAuthority().data()))
            .setAuthentication(new EKSAuthentication(provider, AWS_REGION, AWS_EKS_CLUSTER_NAME, EXPIRY_SECONDS))
            .build();

        ApiKeyAuth auth = (ApiKeyAuth) client.getAuthentication("BearerToken");
        String token = auth.getApiKey().substring("k8s-aws-v1.".length());
        String payload = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);

        int statusCode;
        String message;
        try {
            int namespaceCount = new CoreV1Api(client).listNamespace().execute().getItems().size();
            statusCode = 200;
            message = "Kubernetes API request succeeded, namespaces=" + namespaceCount;
        } catch (ApiException e) {
            statusCode = e.getCode();
            message = "Kubernetes API request failed with HTTP " + e.getCode();
        } finally {
            client.getHttpClient().dispatcher().cancelAll();
            client.getHttpClient().dispatcher().executorService().shutdownNow();
            client.getHttpClient().connectionPool().evictAll();
        }

        System.out.println("Current master decoded payload prefix:");
        System.out.println(payload.substring(0, Math.min(payload.length(), 120)) + "...");
        System.out.println(message);

        assertThat(payload).startsWith("https%3A//");
        assertThat(statusCode).isEqualTo(401);
    }

    @Test
    void fixed_eks_authentication_test() throws IOException {
        ApiClient client = ClientBuilder.standard()
            .setBasePath(cluster.endpoint())
            .setCertificateAuthority(Base64.getDecoder().decode(cluster.certificateAuthority().data()))
            .setAuthentication(new FixedEKSAuthentication(provider, AWS_REGION,
                AWS_EKS_CLUSTER_NAME, EXPIRY_SECONDS))
            .build();

        String[] payload = new String[1];
        client.setHttpClient(client.getHttpClient().newBuilder().addInterceptor((Interceptor.Chain chain) -> {
            Request request = chain.request();
            String authorization = request.header("Authorization");
            String token = authorization.substring("Bearer k8s-aws-v1.".length());
            payload[0] = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
            return chain.proceed(request);
        }).build());

        int statusCode;
        String message;
        try {
            int namespaceCount = new CoreV1Api(client).listNamespace().execute().getItems().size();
            statusCode = 200;
            message = "Kubernetes API request succeeded, namespaces=" + namespaceCount;
        } catch (ApiException e) {
            statusCode = e.getCode();
            message = "Kubernetes API request failed with HTTP " + e.getCode();
        } finally {
            client.getHttpClient().dispatcher().cancelAll();
            client.getHttpClient().dispatcher().executorService().shutdownNow();
            client.getHttpClient().connectionPool().evictAll();
        }

        System.out.println("Fixed decoded payload prefix:");
        System.out.println(payload[0].substring(0, Math.min(payload[0].length(), 120)) + "...");
        System.out.println(message);

        assertThat(payload[0]).startsWith("https://");
        assertThat(statusCode).isEqualTo(200);
    }
}
