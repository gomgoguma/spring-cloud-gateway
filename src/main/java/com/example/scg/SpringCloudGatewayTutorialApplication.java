package com.example.scg;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class SpringCloudGatewayTutorialApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringCloudGatewayTutorialApplication.class, args);
    }

}
