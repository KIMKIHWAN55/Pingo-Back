FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY build/libs/*SNAPSHOT.jar app.jar
EXPOSE 8080
ENV TZ=Asia/Seoul
ENTRYPOINT ["java", "-jar", "app.jar"]