package ec.edu.ups.restclient;

import lombok.extern.slf4j.Slf4j;
import org.asynchttpclient.*;
import org.asynchttpclient.request.body.multipart.StringPart;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
public class VirusTotalClient {

    @Value("${apikey}")
    private String apiKey;

    @Value("${api.virus.total.url}")
    private String apiVirusTotalUrl;

    public String sendPostRequest(String body) {

        DefaultAsyncHttpClientConfig.Builder clientConfigBuilder = new DefaultAsyncHttpClientConfig.Builder();
        try (AsyncHttpClient asyncHttpClient = new DefaultAsyncHttpClient(clientConfigBuilder.build())) {
            BoundRequestBuilder requestBuilder = asyncHttpClient.preparePost(apiVirusTotalUrl);
            requestBuilder.setHeader("Content-Type", "multipart/form-data");
            requestBuilder.setHeader("x-apikey", apiKey);

            requestBuilder.addBodyPart(new StringPart("url", body));

            CompletableFuture<Response> responseFuture = requestBuilder.execute().toCompletableFuture();

            Response response = responseFuture.join();

            if (response.getStatusCode() != 200) throw new RuntimeException("ERROR AL CONSULTAR VIRUS TOTAL");

            return response.getResponseBody();

        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }

    }

    public String sendGetRequest(String newUrl) {

        DefaultAsyncHttpClientConfig.Builder clientConfigBuilder = new DefaultAsyncHttpClientConfig.Builder();
        try (AsyncHttpClient asyncHttpClient = new DefaultAsyncHttpClient(clientConfigBuilder.build())) {
            BoundRequestBuilder requestBuilder = asyncHttpClient.prepareGet(newUrl);
            requestBuilder.setHeader("x-apikey", apiKey);

            CompletableFuture<Response> responseFuture = requestBuilder.execute().toCompletableFuture();

            Response response = responseFuture.join();

            if (response.getStatusCode() != 200) throw new RuntimeException("ERROR AL CONSULTAR VIRUS TOTAL");

            return response.getResponseBody();

        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }

    }


}
