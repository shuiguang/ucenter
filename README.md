# ucenter

为了方便整合Comsenz旗下用户中心同步登录、退出、注册功能，使用java和javascript重写uc_authcode方法。

## 功能
支持纯英文或半角标点的直接加密解密，中文等特殊字符需要编码后加密，解密后解码即可。

## 使用方法

```java
// 密钥
String key = "key";

// 过期时间,单位s
int expiry = 1;

// 加密消息得到密文
String ucAuthcode = UCUtil.ucAuthcode(URLEncoder.encode("我的世界", "UTF-8"), "ENCODE", key, expiry);

// 打印出密文
System.out.println(ucAuthcode);

// 本地解析得到明文
String result2 = UCUtil.ucAuthcode(ucAuthcode, "DECODE", key, expiry);

// 如果未超过expiry,则可以打印出明文
System.out.println("result2="+URLDecoder.decode(result2, "UTF-8"));
```

## 其他语言开发及案例
理论上所有编程语言均能实现ucAuthcode方法，前提是实现相同功能md5加密和base64编码解码便能通过密文在有效期内通信。

javascript案例

参考UCUtil.js、md5.js、base64.js





