# spring-boot-starter-security-qrcode

### 说明


 > Spring Security 整合 扫码登录  的 Spring Boot Starter 实现

1. 依赖zxing 和 redis 服务
2. 已经完成本地对接

![](https://github.com/vindell/spring-boot-starter-security-qrcode/blob/master/二维码扫码登录流程.png)

获取二维码
/authz/qrcode/info
获取二维码UUID绑定的用户信息
/authz/qrcode/bind?uuid=xxx

### Maven

``` xml
<dependency>
	<groupId>${project.groupId}</groupId>
	<artifactId>spring-boot-starter-security-qrcode</artifactId>
	<version>${project.version}</version>
</dependency>
```



### Sample（待补充）

[https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-security-qrcode](https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-security-qrcode "spring-boot-sample-security-qrcode")

