# 域内非域管权限的域信息收集

## 讲在前面

我们在信息内网信息收集的过程中经常被以往或忽视的问题是，通过身份验证的用户（一般来说就是域用户）是可以查看或读取大多数域内的对象机器属性的，问题在于，管理员可能认为，由于这些数据最容易通过管理工具访问，如“Active Directory User and Computers”\(dsa.msc\)或“Active Directory Administrative Center”\(dsa.msc\)，其他人无法看到用户数据\(除了在Outlook的GAL中暴露的内容\)。  
这通常会导致密码数据被放置在用户对象属性或SYSVOL中。那么我们可以从Active Directory中收集到很多数据，这些数据可以帮助我们更新域内信息收集的问题并且为我们进一步的内网渗透做准备。对于防守方来说，了解普通用户帐户在AD中可访问的不同类型的数据是很重要的。

攻击通常以发送给一个或多个域内或非域内用户的鱼叉式钓鱼电子邮件开始，使攻击者能够在目标网络内的计算机上运行他们的恶意代码。一旦攻击者的恶意代码在企业内部运行，第一步就是执行信息探测以发现有用的资源来升级权限、持久化，当然，还有掠夺信息\(通常是组织的“王冠”\)。

这篇文章展示了攻击者如何只用域内普通用户权限来探测Active Directory环境。

注意:本文中的大多数示例使用activedirectory PowerShell模块cmdlet，一个好的替代方案是[HarmJ0y](https://twitter.com/harmj0y)的master版本的[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)\(现在是[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)的一部分\)。

域环境：pingpig.com   windows2008R2-x64   user:Administrator

域客户机：win7SP1-x64  user：test3

![](https://img-blog.csdnimg.cn/2020100215125632.png)

实验环境导入缺少的ActiveDirectory模块：

![](https://img-blog.csdnimg.cn/20201002165523469.png)

注意：此处为实验环境，主机上为基础补丁，且域客户机默认开启了powershell执行权限，与实际渗透有所不同，实际中请仔细分析各类信息。

导入脚本：

> 两种方式都可以导入，按实际情况选择即可：
>
> . .\PowerView.ps1
>
>   
> import-module .\PowerView.ps1

![](https://img-blog.csdnimg.cn/20201002152137793.png)

## 获取活动目录信息 <a id="%E8%8E%B7%E5%8F%96%E6%B4%BB%E5%8A%A8%E7%9B%AE%E5%BD%95%E4%BF%A1%E6%81%AF"></a>

### 森林信息： <a id="%E6%A3%AE%E6%9E%97%E4%BF%A1%E6%81%AF%EF%BC%9A"></a>

> \[System.DirectoryServices.ActiveDirectory.Forest\]::GetCurrentForest\(\)

### ![](https://img-blog.csdnimg.cn/20201002151959104.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)域信息： <a id="%E2%80%8B%E5%9F%9F%E4%BF%A1%E6%81%AF%EF%BC%9A"></a>

> \[System.DirectoryServices.ActiveDirectory.Domain\]::GetCurrentDomain\(\)

![](https://img-blog.csdnimg.cn/20201002152102356.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 森林之间信任关系： <a id="%E6%A3%AE%E6%9E%97%E4%B9%8B%E9%97%B4%E4%BF%A1%E4%BB%BB%E5%85%B3%E7%B3%BB%EF%BC%9A"></a>

> $ForestRootDomain = ‘pingpig.com’  
> \(\[System.DirectoryServices.ActiveDirectory.Forest\]::GetForest\(\(New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext\(‘Forest’, $ForestRootDomain\)\)\)\).GetAllTrustRelationships\(\)

![](https://img-blog.csdnimg.cn/20201002172537294.png)

注：这里未显示，因其未搭建多森林网络，故未显示。[域之间的关系](http://www.baidu.com/)

### 域之间信任： <a id="%E5%9F%9F%E4%B9%8B%E9%97%B4%E4%BF%A1%E4%BB%BB%EF%BC%9A"></a>

```text
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```

![](https://img-blog.csdnimg.cn/20201002172601518.png)

注：这里未显示，因其未搭建多域网络，故未显示。[域之间的关系](http://www.baidu.com/)

### 获取林全局目录（通常每个域控制器也是一个GC） <a id="%E8%8E%B7%E5%8F%96%E6%9E%97%E5%85%A8%E5%B1%80%E7%9B%AE%E5%BD%95%EF%BC%88%E9%80%9A%E5%B8%B8%E6%AF%8F%E4%B8%AA%E5%9F%9F%E6%8E%A7%E5%88%B6%E5%99%A8%E4%B9%9F%E6%98%AF%E4%B8%80%E4%B8%AAGC%EF%BC%89"></a>

```text
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GlobalCatalogs
```

![](https://img-blog.csdnimg.cn/20201002153420677.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**防御：**没有合理的缓解措施。上面这些信息不能也不应该被混淆或隐藏

## 非网络扫描探测域内企业服务 <a id="%E9%9D%9E%E7%BD%91%E7%BB%9C%E6%89%AB%E6%8F%8F%E6%8E%A2%E6%B5%8B%E5%9F%9F%E5%86%85%E4%BC%81%E4%B8%9A%E6%9C%8D%E5%8A%A1"></a>

最简单的探测方法是使用称为“ [SPN扫描](https://adsecurity.org/?p=1508)”的方法，该方法向域控制器询问特定类型的所有服务主体名称（SPN）。这使攻击者可以发现所有类似SQL服务器，Exchange服务器等。有网站维护了[SPN目录列表，其中包括企业中最常见的SPN](https://adsecurity.org/?page_id=183)。SPN扫描也可以发现哪些Windows计算机启用了RDP（TERMSERV），启用了WinRM（WSMAN）等。

注意：为了发现所有企业服务，请同时定位计算机和用户（服务帐户）。

### 查看域内用户\(机器账户和用户账户\)注册的SPN服务信息： <a id="%E6%9F%A5%E7%9C%8B%E5%9F%9F%E5%86%85%E7%94%A8%E6%88%B7(%E6%9C%BA%E5%99%A8%E8%B4%A6%E6%88%B7%E5%92%8C%E7%94%A8%E6%88%B7%E8%B4%A6%E6%88%B7)%E6%B3%A8%E5%86%8C%E7%9A%84SPN%E6%9C%8D%E5%8A%A1%E4%BF%A1%E6%81%AF%EF%BC%9A"></a>

> Get-DomainSpn              注：此处查询使用的此脚本[Get-DomainSpn](https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/ADS/Get-DomainSpn.psm1)

![](https://img-blog.csdnimg.cn/20201002161853987.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**注**：[其他SPN扫描脚本的如何使用](http://hackergu.com/kerberos-sec-spn-search/)

**防御：**没有缓解措施。[服务主体名称（SPN）是Kerberos协议运行所必需的](https://adsecurity.org/?p=230)。

SPN扫描将发现所有支持Kerberos的企业服务。与ActiveDirectory集成的其他企业服务通常会在域“系统”容器中创建一个新的容器\(CN=System,DC=&lt;domain&gt;\)。在域系统容器中存储数据的一些企业应用包括:

SCCM:“系统管理”

有一些像Exchange这样的应用程序在林配置分区“Services”容器中创建容器\(CN=Services,CN= configuration,DC=&lt;domain&gt;\)。

**防御**:没有合理的缓解措施。

### 发现服务帐户 <a id="%E5%8F%91%E7%8E%B0%E6%9C%8D%E5%8A%A1%E5%B8%90%E6%88%B7"></a>

查找服务帐户及使用该帐户注册的服务器信息的最快方法是使用SPN扫描域内具有服务主体名称的用户帐户。

> Get-NetUser -spn

![](https://img-blog.csdnimg.cn/20201002160018714.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

```text
get-aduser -filter {ServicePrincipalName -like "*"} -Properties PasswordLastSet,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation
```

![](https://img-blog.csdnimg.cn/20201002165132141.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**防御**：没有合理的缓解措施。

### 在没有网络扫描的情况下发现计算机 <a id="%E5%9C%A8%E6%B2%A1%E6%9C%89%E7%BD%91%E7%BB%9C%E6%89%AB%E6%8F%8F%E7%9A%84%E6%83%85%E5%86%B5%E4%B8%8B%E5%8F%91%E7%8E%B0%E8%AE%A1%E7%AE%97%E6%9C%BA"></a>

加入Active Directory的每台计算机在AD中都有一个关联的计算机帐户。连接计算机后，有几个与此计算机对象关联的属性会被更新，其中一些非常有用。这些包括：

* Created（创建）
* Modified（修改）
* Enabled（启用）
* Description（描述）
* LastLogonDate \(Reboot\)（最后登录日期\(重新启动\)）
* PrimaryGroupID \(516 = DC\) （主要组ID\(516 =DC\)）
* PasswordLastSet \(Active/Inactive\)OperatingSystem（密码最后设置\(活动\)的操作系统）
* OperatingSystemVersion（操作系统版本）
* OperatingSystemServicePack（操作系统服务版本）
* PasswordLastSet（密码最后设置）
* LastLogonDate \(PowerShell cmdlet attribute\)（最后登录日期\(PowerShell cmdlet属性\)）
* ServicePrincipalName（服务主体名称）
* TrustedForDelegation（信任的代表团）
* TrustedToAuthForDelegation（委托Auth代理）

> Get-NetComputer

![](https://img-blog.csdnimg.cn/20201002163105349.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**注**：这里笔者遇到问题，即指定查询域内所有计算机的属性，但无法在命令行显示出来，未找到解决办法

![](https://img-blog.csdnimg.cn/20201002171927452.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

可以通过将PrimaryGroupID值更改为“ 516”来收集域控制器的相同数据，也可以通过将其更改为“ -filter \*”来获取所有计算机。

```text
get-adcomputer -filter {PrimaryGroupID -eq "516"} -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,PasswordLastSet,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation
```

![](https://img-blog.csdnimg.cn/20201002172412691.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

提供有关Windows OS版本以及加入Active Directory的非Windows设备的有用信息。

查找非Windows设备的一些示例查询：

* 操作系统-如“ \* Samba \*”
* 操作系统-如“ \* OnTap \*”
* 操作系统-如“ \* Data Domain \*”
* 操作系统-如“ \* EMC \*”
* 操作系统-如“ \* Windows NT \*”

**防御**：没有缓解措施。

### 识别管理员帐户 <a id="%E8%AF%86%E5%88%AB%E7%AE%A1%E7%90%86%E5%91%98%E5%B8%90%E6%88%B7"></a>

有两种有效的方法可以在Active Directory中发现具有较高权限的帐户。第一种是标准组枚举方法，该方法标识标准Active Directory管理员组的所有成员：域管理员，管理员，企业管理员等。通常，获取域“管理员”组的递归组成员资格将提供所有AD管理员的列表。 

我[在2015年的DerbyCon上](https://adsecurity.org/?page_id=1352)强调了第二种方法，涉及识别所有属性“ AdminCount”设置为1的帐户。对此的警告是，此查询中返回的帐户可能不再具有管理员权限，因为此值从帐户中删除该帐户后，不会自动重置。有关SDProp和AdminCount属性的更多信息：“[活跃Active Directory持久性＃15：利用AdminSDHolder和SDProp来（重新）获得域管理员权限](https://adsecurity.org/?p=1906)”

```text
get-aduser -filter {AdminCount -eq 1} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf
```

![](https://img-blog.csdnimg.cn/20201002173138935.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**注意**：_这些方法将不会返回具有自定义委托的管理员帐户-最终不是标准AD组成员的管理员帐户。_

**防御**：没有缓解措施。期望攻击者更多地了解哪些帐户拥有对重要资源的更高权限

### 查找管理员组 <a id="%E6%9F%A5%E6%89%BE%E7%AE%A1%E7%90%86%E5%91%98%E7%BB%84"></a>

大多数组织都有自定义管理组，它们具有不同的命名方案，尽管大多数组织都包含“ admin”一词。向AD询问名称中带有“ admin”的所有安全组是一种获取列表的快速方法。

```text
get-adgroup -filter {GroupCategory -eq 'Security' -AND Name -like "*admin*"}
```

![](https://img-blog.csdnimg.cn/20201002173327933.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### **识别域密码策略** <a id="%E8%AF%86%E5%88%AB%E5%9F%9F%E5%AF%86%E7%A0%81%E7%AD%96%E7%95%A5"></a>

可以使用“网络帐户”或AD PowerShell模块“ [Get-ADDefaultDomainPasswordPolicy](https://technet.microsoft.com/en-us/library/ee617244.aspx) ”轻松枚举域密码策略

> Get-ADDefaultDomainPasswordPolicy

![](https://img-blog.csdnimg.cn/20201002175213630.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**防御**：没有合理的缓解措施。

### 识别精细的密码策略 <a id="%E8%AF%86%E5%88%AB%E7%B2%BE%E7%BB%86%E7%9A%84%E5%AF%86%E7%A0%81%E7%AD%96%E7%95%A5"></a>

如果将域功能级别（DFL）设置为“ Windows Server 2008”或更高版本，则可以使用一种称为精细密码策略（FGPP）的新功能，以提供可以应用于用户或组的多种密码策略。 （不是OU）。尽管Microsoft从Windows Server 2008（DFL）开始提供了精细密码策略，但直到Windows Server 2012才更新Active Directory管理中心（ADAC）以支持FGPP管理。从“视图”菜单启用“高级功能” “ Active Directory用户和计算机”中的“选项”，然后向下浏览到“系统”，“密码设置容器”（CN =“密码设置容器”，CN =“系统”，DC = DOMAIN，DC = COM）通常会显示任何域FGPP对象。请注意，如果未启用“高级功能”，则系统容器不可见。

FGPP超越了域密码策略设置，可用于要求更严格的密码策略或为部分域用户启用较少限制的设置。

> Get-ADFineGrainedPasswordPolicy -Filter \*

注：笔者这里在2016和2008的机器上尝试该命令，执行后未显示任何信息

**防御**：没有合理的缓解措施。

### **识别托管服务帐户和组托管服务帐户** <a id="%E8%AF%86%E5%88%AB%E6%89%98%E7%AE%A1%E6%9C%8D%E5%8A%A1%E5%B8%90%E6%88%B7%E5%92%8C%E7%BB%84%E6%89%98%E7%AE%A1%E6%9C%8D%E5%8A%A1%E5%B8%90%E6%88%B7"></a>

Microsoft在Windows Server 2008 R2 DFL中添加了[托管服务帐户（MSA）](https://technet.microsoft.com/en-us/library/dd548356%28v=ws.10%29.aspx)作为一项新功能，该功能可自动管理和更新MSA密码。关键限制是MSA只能链接到运行Windows 7或Windows Server 2008 R2（或更新版本）的单台计算机。

Windows Server 2012 DFL向MSA引入了必需的更新，称为[组托管服务帐户（gMSA）](https://technet.microsoft.com/en-us/library/jj128431.aspx)，该更新使gMSA可以链接到运行Windows 8或Windows Server 2012（或更新版本）的任意数量的计算机。将DFL提升到Windows Server 2012或更高版本后，默认的AD服务帐户创建选项将创建一个新的gMSA（例如，使用AD PowerShell模块cmdlet [New-ADServiceAccount](https://technet.microsoft.com/en-us/library/ee617211.aspx)）。在创建gMSA之前，需要先创建KDS根密钥（_Add-KDSRootKey –EffectiveImmediately_）。

> Get-ADServiceAccount -Filter \* -Properties \*

注：笔者这里在2016和2008的机器上尝试该命令，执行后未显示任何信息

**防御**：没有合理的缓解措施。

### **标识对工作站/服务器具有本地管理员权限的组** <a id="%E6%A0%87%E8%AF%86%E5%AF%B9%E5%B7%A5%E4%BD%9C%E7%AB%99%2F%E6%9C%8D%E5%8A%A1%E5%99%A8%E5%85%B7%E6%9C%89%E6%9C%AC%E5%9C%B0%E7%AE%A1%E7%90%86%E5%91%98%E6%9D%83%E9%99%90%E7%9A%84%E7%BB%84"></a>

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)合并了此功能  
组策略提供了通过受限制的组来强制本地组成员身份的功能，例如OU中所有计算机上的Administrators组。可以通过标识使用受限组的GPO及其应用的OU进行追溯。这将提供具有管理员权限的AD组以及关联的计算机列表。

> Get-NetGPOGroup

注：笔者这里在2016和2008的机器上尝试该命令，执行后未显示任何信息

**防御：**唯一的缓解措施是使域用户无法读取管理本地组的GPO。只有域中的计算机才需要具有读取和处理这些GPO的能力。请注意，一旦攻击者获得了域中一台计算机上的管理员权限，他们就可以使用该计算机帐户来读取GPO。

### 识别Microsoft AppLocker设置 <a id="%E8%AF%86%E5%88%ABMicrosoft%20AppLocker%E8%AE%BE%E7%BD%AE"></a>

[Microsoft AppLocker](https://technet.microsoft.com/en-us/library/dd723686%28v=ws.10%29.aspx)可用于将应用程序执行限制为特定的已批准应用程序。我为AppLocker建议几个不同的阶段：

* 第1阶段：审核模式–审核用户的所有执行及其运行的路径。此日志记录模式提供有关企业中正在运行哪些程序的信息，并将此数据记录到事件日志中。
* 阶段2：“黑名单模式” –将AppLocker配置为阻止执行用户的主目录，配置文件路径和用户具有写权限的临时文件位置（例如c：\ temp）中的任何文件。
* 阶段3：“文件夹白名单模式” –通过添加新规则将AppLocker配置为在阶段2上构建，以仅允许执行特定文件夹（例如c：\ Windows和c：\ Program Files）中的文件。
* 阶段4：“应用程序白名单” –盘点企业环境中正在使用的所有应用程序，并按位置和哈希（最好是数字签名）将这些应用程序列入白名单。这样可以确保仅批准的组织应用程序可以执行。

问题是AppLocker是通过组策略配置的，该策略通常保持默认设置，这使所有域用户都能够读取配置。

**防御：**唯一的缓解措施是使域用户无法读取管理本地组的GPO。只有域中的计算机才需要具有读取和处理这些GPO的能力。请注意，一旦攻击者获得了域中一台计算机上的管理员权限，他们就可以使用该计算机帐户来读取GPO。

### **识别Microsoft EMET设置** <a id="%E8%AF%86%E5%88%ABMicrosoft%20EMET%E8%AE%BE%E7%BD%AE"></a>

[Microsoft增强的缓解经验工具包（EMET）](https://technet.microsoft.com/en-us/security/jj653751)有助于防止利用应用程序漏洞（包括大约0天）。它是一种免费产品，可以有效地“包装”流行的应用程序，因此，在尝试利用漏洞进行攻击时，尝试将在“包装器”处停止，而不会在操作系统中进行。  
企业通常使用组策略来配置EMET，该EMET通常保持默认状态，从而使所有域用户都能够读取配置。

**防御：**唯一的缓解措施是使域用户无法读取管理本地组的GPO。只有域中的计算机才需要具有读取和处理这些GPO的能力。请注意，一旦攻击者获得了域中一台计算机上的管理员权限，他们就可以使用该计算机帐户来读取GPO。

### **识别Microsoft LAPS委派** <a id="%E8%AF%86%E5%88%ABMicrosoft%20LAPS%E5%A7%94%E6%B4%BE"></a>

[Microsoft本地管理员密码解决方案（LAPS）](https://adsecurity.org/?p=1790)是管理企业中计算机本地管理员帐户密码的绝佳选择。LAPS向AD计算机对象添加了两个新属性，一个属性用于存储本地Admin密码，另一个属性用于跟踪上次更改密码的时间。LAPS GPO用于配置LAPS客户端，以确定何时更改密码，更改密码的长度，管理帐户等。计算机的本地管理员密码是由LAPS客户端在计算机上创建的，该密码被设置为LAPS密码属性（ms-Mcs-AdmPwd），并在本地更改。为了使管理员可以使用该密码，需要委派对ms-Mcs-AdmPwd的读取权限。可以通过枚举属性上的安全ACL来标识此委派。

**防御：**唯一的缓解措施是使域用户无法读取管理本地组的GPO。只有域中的计算机才需要具有读取和处理这些GPO的能力。请注意，一旦攻击者获得了域中一台计算机上的管理员权限，他们就可以使用该计算机帐户来读取GPO。

### **发现域SYSVOL共享中的管理员凭据** <a id="%E5%8F%91%E7%8E%B0%E5%9F%9FSYSVOL%E5%85%B1%E4%BA%AB%E4%B8%AD%E7%9A%84%E7%AE%A1%E7%90%86%E5%91%98%E5%87%AD%E6%8D%AE"></a>

管理员通常将凭据放在脚本或组策略中，这些脚本或注释最终以SYSVOL的形式出现。  
有关此问题的更多信息，包括缓解措施：“[在SYSVOL中查找密码和利用组策略首选项](https://adsecurity.org/?p=2288)”

## 总结： <a id="%E6%80%BB%E7%BB%93%EF%BC%9A"></a>

这些只是一些有趣的数据项，可以作为域用户从Active Directory轻松收集。希望防守者能够在您的企业中引起重视，并据此调整当前策略。

