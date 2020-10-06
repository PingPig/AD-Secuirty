# 域内权限介绍——域控制器和AD管理

## 讲在前面：

Active Directory具有除Domain Admins组之外的多个管理级别。这篇文章讲述通常我们会如何来管理Active Directory以及相关角色和权限的信息。

## 主要域内管理员组 <a id="%E4%B8%BB%E8%A6%81%E5%9F%9F%E5%86%85%E7%AE%A1%E7%90%86%E5%91%98%E7%BB%84"></a>

### \*\*\*\*[**Domain Admins**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_DomainAdmins)\*\*\*\*

这是大多数人在讨论Active Directory管理时想到的一个Active Directory组。默认情况下，该组在所有加入域的服务器、工作站、域控制器以及Active Directory上具有完全的管理员权限。这些系统加入Active Directory后，域管组会将其添加到计算机的本地Administrators组中，因此它拥有对加入域内的所有计算机的管理权限

![](https://img-blog.csdnimg.cn/20201002225919310.png)

### \*\*\*\*[**Enterprise Admins**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_EntAdmins)\*\*\*\*

这是林根域中的一个组，它对Active Directory林中的每个域都有完整的Active Directory权限。在林中的每个域的Administrator组中的成员都是有资格来被赋予该权限的。

![](https://img-blog.csdnimg.cn/20201002225933137.png)

### \*\*\*\*[**Administrator**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_Admins)\*\*\*\*

Active Directory域中的Administrators组是对Active Directory和域控制器具有默认管理权限的组，域管理员及企业管理员才有权限增减其组内成员。

![](https://img-blog.csdnimg.cn/20201002230808848.png)

### \*\*\*\*[**Schema Admins**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_SchemaAdmins)\*\*\*\*

是林根域中的一个组，可以修改Active Directory林架构。

![](https://img-blog.csdnimg.cn/20201002230831374.png)

**防守方建议：**因为Administrators组是提供对Active Directory和Domain Controllers完整权限的域组，因此密切监视此组的成员关系（包括所有嵌套的组）是非常重要的。PowerShell命令里的 cmdlet模块中“ Get-ADGroupMember”命令可以提供组成员身份信息。

![](https://img-blog.csdnimg.cn/20201002224956779.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 小结： <a id="%E5%B0%8F%E7%BB%93%EF%BC%9A"></a>

Active Directory中的默认组通常具有广泛的权限——比实际所需要的权限更多。因此，我们不建议使用这些组进行委派。在一般的情况下，自定义委派需要确保[遵循最小特权原则](https://en.wikipedia.org/wiki/Principle_of_least_privilege)。

## 类管理员组 <a id="%E7%B1%BB%E7%AE%A1%E7%90%86%E5%91%98%E7%BB%84"></a>

在默认情况下作用域适用于域控制器，所以下面这些组应当添加“ DC”前缀。并且由于它们对域控制器具有较高的权限，我们应该把下例组的组内成员视为有效的域管

### \*\*\*\*[**备份操作员（Backup Operators）**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_BackupOperators) ****

备份操作员被授予登录、关闭和在域控制器上执行备份/恢复操作的能力\(通过默认的域控制器策略GPO分配\)。此组不能直接修改AD管理组，但其关联的特权提供了升级到AD管理的路径。备份操作符能够调度可能提供升级路径的任务。它们还能够清除域控制器上的事件日志。

![](https://img-blog.csdnimg.cn/20201002232324493.png)

### [**打印操作员（Print Operators ）**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_PrintOperators)\*\*\*\*

打印操作符被授予在域控制器上管理打印机和加载/卸载设备驱动程序以及管理Active Directory中的打印机对象的能力。默认情况下，该组可以登录到域控制器并关闭它们。此组不能直接修改AD管理组。

![](https://img-blog.csdnimg.cn/20201002232339809.png)

### \*\*\*\*[**服务器操作员（Server Operators ）**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_ServerOperators)\*\*\*\*

服务器操作员被授予在域控制器\(通过缺省域控制器策略GPO分配\)上登录、关闭和执行备份/恢复操作的能力。此组不能直接修改AD管理组，但关联的特权提供了升级到AD管理的路径。

![](https://img-blog.csdnimg.cn/20201002232352726.png)

### \*\*\*\*[**远程桌面用户（Remote Desktop Users ）**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_REmoteDesktopUsers)\*\*\*\*

远程桌面用户是为方便地提供对系统的远程访问而设计的域组。在许多AD域中，这个组被添加到缺省域控制器策略GPO中的“允许通过终端服务登录”中，为DC提供潜在的远程登录功能。

![](https://img-blog.csdnimg.cn/20201002232405920.png)

我们还看到很多时候，通过链接到域控制器OU的GPO进行以下配置：

* **远程桌面用户**：通常通过链接到域控制器OU的组策略被授予“允许通过终端服务登录”的权限。
* **服务器操作员**：通过链接到域控制器OU的组策略被授予“允许通过终端服务登录”的权限。
* **服务器操作员**：通过GPO被授予“作为批处理作业登录”的权限，从而可以计划任务。

查看链接到域和域控制器OU的GPO，并确保GPO设置合适。  
我们经常发现服务器GPO也链接到域控制器OU，并且将“ Server Admins”组添加到本地Administrators组。由于域控制器没有“本地”管理员组，因此DC通过添加服务器管理员来更新域管理员组。此方案使服务器管理员的所有成员成为Active Directory管理员。

**防守方建议**：应仔细检查授予域控制器本地登录权限的任何组/帐户。服务器操作员和备份操作员对域控制器具有较高的权限，应受到监视。Active Directory PowerShell cmdlet“ Get-ADGroupMember”可以提供组成员身份信息。

## 其他权限提升的默认组： <a id="%E5%85%B6%E4%BB%96%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87%E7%9A%84%E9%BB%98%E8%AE%A4%E7%BB%84%EF%BC%9A"></a>

### \*\*\*\*[**帐户操作员（Account Operators）**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_AccountOperators) ****

有权修改域中的帐户和组。还具有默认情况下登录到域控制器的能力（通过“默认域控制器策略” GPO分配）。尽管关联的特权提供了升级到AD admin的路径，但该组不能直接修改AD admin组。

![](https://img-blog.csdnimg.cn/20201003003012928.png)

### \*\*\*\*[**DNSAdmins**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_DnsAdmins)\*\*\*\*

具有对Microsoft Active Directory DNS的管理访问权限，通常被授予登录域控制器的功能。  
请注意，默认情况下，DNSAdmins组的成员能够在域控制器上运行DLL，该DLL可以提供对域管理员权限的特权升级：[ https](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83) : [ //medium.com/@esnesenon/feature-not-bug-dnsadmin-to -DC折中一线a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)

![](https://img-blog.csdnimg.cn/2020100300302696.png)

### \*\*\*\*[**组策略创建者所有者（Group Policy Creator Owners）**](https://technet.microsoft.com/en-us/library/dn579255%28v=ws.11%29.aspx#BKMK_GPCreatorsOwners)\*\*\*\*

可以在域中创建，修改和删除组策略。

授予域控制器上的组和帐户的大多数权限是由“默认域控制器策略”组策略应用的。这些通常是在“用户权限分配”部分中定义的，我们在执行[Active Directory安全评估](https://trimarcsecurity.com/security-services)时会对其进行审核，因为对于谁拥有DC权限通常很有启发意义。从Windows 2000到现在，“默认域控制器策略”中的设置已更改了多年。请注意，如果您使用Windows 2000或2003服务器提升了Active Directory，则即使运行Windows Server 2016，该策略仍将包含那些原始设置（假定没有人更改策略设置）。

![](https://img-blog.csdnimg.cn/20201003003040201.png)

## **敏感域控制器用户权限分配：** <a id="%E6%95%8F%E6%84%9F%E5%9F%9F%E6%8E%A7%E5%88%B6%E5%99%A8%E7%94%A8%E6%88%B7%E6%9D%83%E9%99%90%E5%88%86%E9%85%8D%EF%BC%9A"></a>

### \*\*\*\*[**允许本地登录-Allow log on locally**](https://technet.microsoft.com/en-us/library/dn221980%28v=ws.11%29.aspx)\*\*\*\*

此策略设置确定哪些用户可以在计算机上启动远程桌面服务进行交互式会话。域内用户具有此权限才能在域内进行远程桌面会话  
**注意：**  
没有此权限的用户如果具有“允许通过远程桌面服务登录”权限，则仍然可以在计算机上启动远程交互式会话。

![](https://img-blog.csdnimg.cn/20201003004222816.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**备份文件和目录-Back-up files & directories**](https://technet.microsoft.com/en-us/library/dn221961%28v=ws.11%29.aspx)\*\*\*\*

此权限决定哪些用户可以绕过文件、目录、注册表和其他持久性对象权限，以便对系统进行备份。只有当应用程序试图通过备份工具\(如NTBACKUP.EXE\)访问NTFS备份应用程序编程接口\(API\)时，这个用户权限才有效。否则，应用标准文件和目录权限。

此用户权限类似于将以下权限授予您在系统上的所有文件和文件夹中选择的用户或组:

* 遍历文件夹/执行文件
* 文件夹列表/读取数据
* 读属性
* 阅读扩展属性
* 阅读权限
* 默认在工作站和服务器上:
* 管理员
* 备份操作
* 域控制器的默认值:
* 管理员
* 备份操作
* 服务器运营商

![](https://img-blog.csdnimg.cn/20201003003541992.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**使计算机和用户帐户受信任进行委派-SeEnableDelegationPrivilege**](https://technet.microsoft.com/en-us/library/dn221977%28v=ws.11%29.aspx)\*\*\*\*

信任计算机和用户帐户可以执行委派，此安全设置确定哪些用户可以在用户或计算机对象上设置“已为委派信任”设置。被授予此权限的用户或对象必须具有对用户或计算机对象上的帐户控制标志的写入访问权限。在已为委派信任的计算机上\(或用户环境下\)运行的服务器进程可以使用客户端委派的凭据访问另一台计算机上的资源，只要该客户端帐户没有设置“帐户无法委派”帐户控制标志。此用户权限是在默认域控制器组策略对象\(GPO\)以及工作站和服务器的本地安全策略中进行定义的。

![](https://img-blog.csdnimg.cn/20201003003606946.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**从远程系统强制关机-Force shutdown from a remote system**](https://technet.microsoft.com/en-us/library/dn221951%28v=ws.11%29.aspx)\*\*\*\*

此安全设置确定允许哪些用户从网络上的远程位置关闭计算机。误用此用户权限会导致拒绝服务。此用户权限是在默认域控制器组策略对象\(GPO\)以及工作站和服务器的本地安全策略中进行定义的。

![](https://img-blog.csdnimg.cn/20201003003627846.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**作为批处理作业登录-Log on as a batch job**](https://technet.microsoft.com/en-us/library/dn221944%28v=ws.11%29.aspx)\*\*\*\*

此安全设置使用户能够通过批处理队列实用程序登录，并仅提供用于与旧版本的 Windows 的兼容性。

例如，当用户通过任务计划程序提交作业时，该任务计划程序将用户作为批处理用户而不是作为交互式用户登录。

![](https://img-blog.csdnimg.cn/20201003003702513.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**作为服务登录-Log on as a service**](https://technet.microsoft.com/en-us/library/dn221981%28v=ws.11%29.aspx)\*\*\*\*

此安全设置可使安全主体作为服务登录。可以将服务配置为在本地系统、本地服务或网络服务帐户下运行，这些帐户具有作为服务登录的内置权限。任何在单独用户帐户下运行的服务都必须分配有该权限。

![](https://img-blog.csdnimg.cn/20201003003718337.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**管理审核和安全日志-Manage auditing and security log**](https://technet.microsoft.com/en-us/library/cc957161.aspx)\*\*\*\*

此安全设置确定哪些用户可以为各种资源\(如文件、Active Directory 对象和注册表项\)指定对象访问审核选项。

此安全设置通常不允许用户启用文件和对象访问审核。若要启用此审核，则必须在 Computer Configuration\Windows Settings\Security Settings\Local Policies\Audit Policies 中配置审核对象访问设置。

你可以在事件查看器的安全日志中查看审核过的事件。具有此权限的用户还可以查看和清除安全日志。

![](https://img-blog.csdnimg.cn/20201003003737326.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**恢复文件和目录-Restore files & directories**](https://technet.microsoft.com/en-us/library/dn221962%28v=ws.11%29.aspx)\*\*\*\*

此安全设置确定在还原备份的文件和目录时哪些用户可以绕过文件、目录、注册表和其他永久对象权限，以及确定哪些用户可以将任何有效的安全主体设置为对象的所有者。特殊情况下，此用户权限类似于向系统上所有文件和文件夹涉及到的用户或组授予下列权限:

遍历文件夹/执行文件  
写入

![](https://img-blog.csdnimg.cn/20201003003800393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**同步目录服务数据-SeSyncAgentPrivilege**](https://technet.microsoft.com/en-us/library/dn221988%28v=ws.11%29.aspx)\*\*\*\*

此安全设置确定哪些用户和组有权同步所有目录服务数据。这也称为 Active Directory 同步。

![](https://img-blog.csdnimg.cn/20201003003822523.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### \*\*\*\*[**取得文件或其他对象的所有权-SeTakeOwnershipPrivilege**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)\*\*\*\*

此安全设置确定哪些用户可以取得系统中任何安全对象\(包括 Active Directory 对象、文件和文件夹、打印机、注册表项、进程以及线程\)的所有权。

**注意:**

分配此用户权限可能有安全风险。由于对象所有者具有对象的完全控制权限，请仅向受信任的用户分配此用户权限。

![](https://img-blog.csdnimg.cn/20201002225131868.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

有关如何通过修改GPO来提高域控制器安全性的具体建议，请参见“[保护域控制器以提高Active Directory安全性](https://adsecurity.org/?p=3377)”一文。

## **默认组和通过默认域控制器策略提供的权限：**

请注意，AD“内置”管理员组被授予大多数权限。

### 通过此GPO为**服务器操作员**提供以下权利：

* 允许本地登录
* 备份文件和目录
* 从远程系统强制关机
* 恢复文件和目录
* 关闭系统

### 通过此GPO为**备份操作员**提供以下权利：

* 允许本地登录
* 备份文件和目录
* 作为批处理作业登录
* 管理审核和安全日志
* 恢复文件和目录
* 关闭系统

### 通过此GPO为**打印操作员**提供以下权利：

* 允许本地登录
* 加载和卸载设备驱动程序
* 关闭系统 

我希望这篇文章可以帮助人们更好地理解内置AD组对域控制器的默认权限。

