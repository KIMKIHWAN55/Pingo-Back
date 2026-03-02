package com.pingo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.File;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    // application.properties 에 설정된 파일 저장 최상위 경로 (예: C:/pingo_back/uploads/)
    @Value("${file.upload.path}")
    private String resourcePath;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // 프론트엔드가 "/images/~~~" 로 이미지를 요청하면,
        // 서버의 "file:경로/uploads/images/~~~" 폴더에서 사진을 찾아서 돌려주도록 매핑!
        registry.addResourceHandler("/images/**")
                .addResourceLocations("file:" + resourcePath + File.separator + "images" + File.separator);
    }
}