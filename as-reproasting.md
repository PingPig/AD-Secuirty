# AS-REPRoasting



## 讲在前面：

最近笔者发布的几篇文章，大家不难发现，都是和kerberos协议相关的。国内外各类的研究员对于该协议的研究愈发的深入，从该协议产生的漏洞就会越来越多甚至越来越严重。当然这只是笔者的一点拙见。

在介绍了Kerberoasting后，与其分不开的一个漏洞AS-REPRoasting我们也要介绍一下。当然，该漏洞依然要建立在受害用户没有使用强壮的符合复杂策略的密码前提下。同时也要强调该漏洞并没有Kerberoasting出彩

## 简介：

对于域用户，如果设置了选项”Do not require Kerberos preauthentication（不要求**kerberos预身份认证**）”，此时向域控制器的88端口发送AS-REQ请求，对收到的AS-REP内容重新组合，能够拼接成”Kerberos 5 AS-REP etype 23”\(18200\)的格式，接下来可以使用hashcat对其破解，最终获得该用户的明文口令，但默认情况下，该选项不会开启。

![](https://img-blog.csdnimg.cn/20201006175412305.png)

**利用条件：**

* **你当前的用户拥有对目标用户GenericWrite / GenericAll权限**
* **用户密码可能较为薄弱**

进行Kerberos预身份验证的原因是为了防止离线密码猜测。尽管AS-REP 票证本身已使用 服务密钥（在本例中为krbtgt哈希）进行了加密，但AS-REP“已加密部分”却使用客户端密钥（即我们为其发送AS-REQ的用户密钥）进行了加密 。如果启用了不要求**kerberos预身份认证**，则攻击者可以为开启该选项的用户发送AS-REQ，从而获得指定用户的AS-REP并进行离线爆破。

### 查询满足条件的用户

使用powerview

寻找满足条件的用户（LDAP查询满足条件\(userAccountControl:1.2.840.113556.1.4.803:=4194304\)）

![](https://img-blog.csdnimg.cn/20201006173922925.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 开启选项

```text
Set-DomainObject -Identity test2 -XOR @{userAccountControl=4194304} -Verbose
```

![](https://img-blog.csdnimg.cn/20201006174714563.png)

**注意：**  
开启和关闭都为同一条命令，命令本身执行的异或操作，两次异或等于未修改原数值。

### 导出hash

使用[ASREPRoast.ps1](https://github.com/HarmJ0y/ASREPRoast)

注意：笔者这里使用该ps1脚本在实验环境中并未能提取到hash，所以使用的[Rubeus](https://github.com/GhostPack/Rubeus)

```text
Rubeus.exe asreproast
```

![](https://img-blog.csdnimg.cn/20201006174954657.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 离线破解

拼接成hashcat能够识别的格式需要在`$krb5asrep`后面添加`$23`,hashcat使用字典破解的参数如下：

```text
hashcat -m 18200 'hash' /temp/pwd.txt -o found.txt --force
```

![](https://img-blog.csdnimg.cn/20201006175211368.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

## 缓解措施

* 确保域内不存在开启”Do not require Kerberos preauthentication”的用户
* 域用户强制使用复杂口令，提高被字典和暴力破解的难度

