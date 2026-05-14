/*
Copyright 2023 The Kubernetes Authors.
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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;

/**
 * EKS cluster authentication which generates a bearer token from AWS AK/SK. It doesn't require an "aws"
 * command line tool in the $PATH.
 */
public class FixedEKSAuthentication extends RefreshAuthentication {

    private static final Logger log = LoggerFactory.getLogger(FixedEKSAuthentication.class);
    private static final int MAX_EXPIRY_SECONDS = 60 * 15;

    /**
     * Instantiates a new Eks authentication.
     *
     * @param provider    the AWS credential provider
     * @param region      the region where EKS cluster at
     * @param clusterName the EKS cluster name
     */
    public FixedEKSAuthentication(AwsCredentialsProvider provider, String region, String clusterName) {
        this(provider, region, clusterName, MAX_EXPIRY_SECONDS);
    }

    public FixedEKSAuthentication(AwsCredentialsProvider provider, String region, String clusterName, int expirySeconds) {
        this(provider, region, clusterName, expirySeconds, Clock.systemUTC());
    }

    FixedEKSAuthentication(
            AwsCredentialsProvider provider, String region, String clusterName, int expirySeconds, Clock clock) {
        super(
                new EksTokenSupplier(provider, region, clusterName, cappedExpirySeconds(expirySeconds)),
                Duration.of(cappedExpirySeconds(expirySeconds), ChronoUnit.SECONDS),
                clock);
        setExpiry(Instant.now(clock).plus(cappedExpirySeconds(expirySeconds), ChronoUnit.SECONDS));
    }

    private static int cappedExpirySeconds(int expirySeconds) {
        return Math.min(expirySeconds, MAX_EXPIRY_SECONDS);
    }

    private static class EksTokenSupplier implements Supplier<String> {
        private final AwsCredentialsProvider provider;
        private final String region;
        private final String clusterName;
        private final int expirySeconds;
        private final URI stsEndpoint;

        EksTokenSupplier(AwsCredentialsProvider provider, String region, String clusterName, int expirySeconds) {
            this.provider = provider;
            this.region = region;
            this.clusterName = clusterName;
            this.expirySeconds = expirySeconds;
            this.stsEndpoint = URI.create("https://sts." + this.region + ".amazonaws.com");
        }

        @Override
        public String get() {
            return generateToken();
        }

        private String generateToken() {
            SdkHttpRequest httpRequest = generateStsRequest();
            String presignedUrl = requestToPresignedUrl(httpRequest);
            String encodedUrl = presignedUrlToEncodedUrl(presignedUrl);
            log.info(
                    "Generated BEARER token for ApiClient, expiring at {}",
                    Instant.now().plus(expirySeconds, ChronoUnit.SECONDS));
            return "k8s-aws-v1." + encodedUrl;
        }

        private static String presignedUrlToEncodedUrl(String presignedUrl) {
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(presignedUrl.getBytes(StandardCharsets.UTF_8));
        }

        private SdkHttpRequest generateStsRequest() {
            return SdkHttpRequest.builder()
                    .uri(stsEndpoint)
                    .encodedPath("/")
                    .putRawQueryParameter("Version", "2011-06-15")
                    .putRawQueryParameter("Action", "GetCallerIdentity")
                    .method(SdkHttpMethod.GET)
                    .putHeader("x-k8s-aws-id", clusterName)
                    .build();
        }

        private String requestToPresignedUrl(SdkHttpRequest httpRequest) {
            AwsV4HttpSigner signer = AwsV4HttpSigner.create();
            SignedRequest signedRequest =
                    signer.sign(r -> r.identity(this.provider.resolveCredentials())
                            .request(httpRequest)
                            .putProperty(AwsV4HttpSigner.SERVICE_SIGNING_NAME, "sts")
                            .putProperty(AwsV4HttpSigner.REGION_NAME, region)
                            .putProperty(AwsV4HttpSigner.AUTH_LOCATION, AwsV4HttpSigner.AuthLocation.QUERY_STRING)
                            .putProperty(
                                    AwsV4HttpSigner.EXPIRATION_DURATION,
                                    Duration.of(expirySeconds, ChronoUnit.SECONDS)));
            SdkHttpRequest request = signedRequest.request();
            return request.getUri().toString();
        }
    }
}
