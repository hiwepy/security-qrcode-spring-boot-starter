# security-qrcode-spring-boot-starter

### 说明


 > Spring Security 整合 扫码登录  的 Spring Boot Starter 实现

1. 依赖zxing 和 redis 服务
2. 已经完成本地对接

![](https://github.com/vindell/security-qrcode-spring-boot-starter/blob/master/二维码扫码登录流程.png)

获取二维码
/authz/qrcode/info
获取二维码UUID绑定的用户信息
/authz/qrcode/bind?uuid=xxx

### Maven

``` xml
<dependency>
	<groupId>${project.groupId}</groupId>
	<artifactId>security-qrcode-spring-boot-starter</artifactId>
	<version>1.0.0-SNAPSHOT</version>
</dependency>
```



### Sample（待补充）

[https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-security-qrcode](https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-security-qrcode "spring-boot-sample-security-qrcode")

