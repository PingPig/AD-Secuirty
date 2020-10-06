# 监控Active Directory特权和特权帐户



## 讲在前面： <a id="%E8%AE%B2%E5%9C%A8%E5%89%8D%E9%9D%A2%EF%BC%9A"></a>

自从攻击者，Red Teamer和渗透测试人员意识到Active Directory的控制权可以为渗透提供强大的力量以来，Active Directory Recon便成为新的热点。

这篇文章详细介绍了如何在Active Directory中发挥敏感特殊权限的作用，以及如何最好地发现谁在AD中拥有哪些权限。当我们为客户执行一个Active Directory的安全评估时,我们所需要囊括的数据点都列在这篇文章中,包括特权组和与之相关联的权限。我所认为的方法是对Active Directory进行全面排查，将关联的权限映射为权限，并将这些权限关联到适当的组\(或帐户\)。现在是时候获取有关AD权限的更多信息了。本文中的示例使用[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)  PowerShell cmdlet。

**注意：标红的地方是极度危险的，存在可被攻击或利用的点，攻击者和防守者需要极度重视**

## **Active Directory的特殊权限** <a id="Active%20Directory%E7%9A%84%E7%89%B9%E6%AE%8A%E6%9D%83%E9%99%90"></a>

关于AD特殊权限的问题一般来讲就是如何确定域内每个组在实际情况下所需要的权限，但目前来看管理员没有办法完全了解某个组成员实际拥有的权限会带来那些潜在的影响。按照渗透步骤来看所有攻击者都是利用对AD的访问（尽管不总是以特殊权限访问）来破坏Active Directory

经常被忽略的关键点是，对Active Directory和关键资源的权限不仅仅是组成员权限，而是用户拥有的组合权限，它由以下几个部分组成:

* Active Directory组成员身份。
* 在计算机上具有特权的AD组
* 通过修改默认权限（对于安全主体，包括直接权限和间接权限）对AD对象的委派权限。
* SIDHistory中分配给AD对象的SID的权限。
* 组策略对象的委派权限。
* 通过组策略（或本地策略）在工作站，服务器和域控制器上配置的用户权限分配定义了这些系统上的提升的权限。
* 一台或多台计算机上的本地组成员身份（类似于GPO分配的设置）。
* 共享文件夹的委派权限。

## 组成员 <a id="%E7%BB%84%E6%88%90%E5%91%98"></a>

枚举组成员是在Active Directory中发现特权帐户的简单方法，尽管它通常不能说明全部情况。但是你看到成员拥有域管理员、管理员和企业管理员的资格，就显而易见的知道它拥有完整的域/森林管理员、创建自定义组并委托对资源的特殊权限。

该命令显示使用PowerView查找敏感组并列出组成员

```text
get-netgroup
```

![](https://img-blog.csdnimg.cn/20201003134200318.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

[具有默认提升权限的组](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)

### 账户操作员组-**Account Operators** <a id="%E8%B4%A6%E6%88%B7%E6%93%8D%E4%BD%9C%E5%91%98%E7%BB%84-Account%20Operators"></a>

* 帐户操作员组向用户授予有限的帐户创建权限。该组的成员可以创建和修改大多数类型的帐户，包括用户账户，本地组和全局组的帐户，并且组内成员拥有从本地登录到域控制器的权限。
* SID/RID:S-1-5-32-548
* 帐户操作员组的成员没有修改[管理员](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)组，[服务器操作员](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)组，[帐户操作员](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)组，[备份操作员](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)组或[打印操作员](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)组内的成员属性的权限。

![](https://img-blog.csdnimg.cn/20201003134506289.png)

**注意：**

* 默认情况下，该组内是没有成员的，加入该组的成员是拥有创建和管理域中的用户和组的权限的。它可以向服务器操作员组内添加成员，而服务器操作员组内的成员又可以修改域控制器设置。
* 所以最好的办法是：保持该组内默认没有成员的情况，并且不要将该组委派任何服务。该默认组不能重命名，删除或移动。

### **管理员组-Administrators** <a id="%E7%AE%A1%E7%90%86%E5%91%98%E7%BB%84-Administrators"></a>

Administrators组的成员具有对计算机的完整且不受限制的访问，如果计算机被提升为域控制器，则组成员具有对域有完整且不受限制的访问

SID/RID:S-1-5-32-544

![](https://img-blog.csdnimg.cn/20201003135857591.png)

**注意：**

* Administrators组默认的权限可以让其成员完全控制系统，并且可以增删改所有管理组内成员的身份，该组不能重命名，删除或移动。
* 成员资格可以由以下组的成员修改：默认服务管理员，域管理员或企业管理员。

### **允许的RODC密码复制组-Allowed RODC Password Replication Group** <a id="%E5%85%81%E8%AE%B8%E7%9A%84RODC%E5%AF%86%E7%A0%81%E5%A4%8D%E5%88%B6%E7%BB%84-Allowed%20RODC%20Password%20Replication%20Group"></a>

* 该组的成员可以在成功进行身份验证（包括用户和计算机帐户）后在RODC上缓存其域的密码
* SID/RID:S-1-5-21-&lt;domain&gt;-571
* 该安全组的功能是管理RODC（只读域控制器-read-only-domain-controller）的密码复制策略。

![](https://img-blog.csdnimg.cn/20201003141152926.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**注意：**

默认情况下该组是没有成员，但如果你在域内创建了新的只读域控制器，但未在该安全组内添加的用户的话，会导致新的只读域控制器不缓存用户凭据。

### **备份操作员-Backup Operators** <a id="%E5%A4%87%E4%BB%BD%E6%93%8D%E4%BD%9C%E5%91%98-Backup%20Operators"></a>

备份操作员组内的成员为了备份和恢复计算机上的所有文件可以不管保护这些文件的权限如何，备份操作人员还具有可以登录和关闭计算机的权限，该组无法重命名、删除或移动。

SID/RID:S-1-5-32-551

![](https://img-blog.csdnimg.cn/20201003141954137.png)

**注意：**

* 默认情况下，这个内置组没有成员，它的成员可以由以下组内成员增删改:默认服务管理员、域管理员或企业管理员
* 该组内成员不能修改任何管理组的成员身份。虽然该组成员不能更改服务器设置或修改AD的配置，但他们却拥有替换域控制器上的文件\(包括操作系统文件\)所需的权限。因此，此组的成员被视为服务管理员。

### **证书服务DCOM访问组-Certificate Service DCOM Access** <a id="%E8%AF%81%E4%B9%A6%E6%9C%8D%E5%8A%A1DCOM%E8%AE%BF%E9%97%AE%E7%BB%84-Certificate%20Service%20DCOM%20Access"></a>

此组的成员可以连接到企业中的证书颁发机构

SID/RID: S-1-5-32-&lt;domain&gt;-574

![](https://img-blog.csdnimg.cn/20201003142740190.png)

### 证书发布者组-**Cert Publishers** <a id="%E8%AF%81%E4%B9%A6%E5%8F%91%E5%B8%83%E8%80%85%E7%BB%84-Cert%20Publishers"></a>

证书发布者组的成员被授权为Active Directory中的用户对象发布证书

 SID/RID: S-1-5-&lt;domain&gt;-517

![](https://img-blog.csdnimg.cn/20201003142918689.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 分布式COM用户组-**Distributed COM Users** <a id="%E5%88%86%E5%B8%83%E5%BC%8FCOM%E7%94%A8%E6%88%B7%E7%BB%84-Distributed%20COM%20Users"></a>

分布式COM用户组的成员可以在计算机上启动、激活和使用分布式COM对象。组件对象模型\(COM\)是一个独立于平台的、分布式的、面向对象的系统，用于创建可交互的二进制软件组件。分布式组件对象模型\(DCOM\)允许应用程序分布在对您和应用程序最有意义的位置上。此组以SID的形式出现，直到域控制器成为主域控制器，并保持操作主角色\(也称为灵活单主操作或FSMO\)。

SID/RID: S-1-5-32-562

![](https://img-blog.csdnimg.cn/20201003143126639.png)

### **Dns管理员-DnsAdmins** <a id="Dns%E7%AE%A1%E7%90%86%E5%91%98-DnsAdmins"></a>

该组的成员具有AD DNS的管理权限，并且可以在作为DNS服务器运行的域控制器上通过DLL运行代码。

 S-1-5-21-&lt;domain&gt;-1102

DNSAdmins组的成员可以访问网络DNS信息。默认权限如下：允许：读取，写入，创建所有子对象，删除子对象，特殊权限。

![](https://img-blog.csdnimg.cn/20201003143542895.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**注意：**

默认情况下，域控制器也是DNS服务器。DNS服务器需要几乎每个域用户都可以访问和使用。反过来，这又暴露了域控制器上的某些攻击面，一方面是DNS协议本身，另一方面是基于RPC的管理协议。在某些情况下我们可以利用其功能在无需成为域管理员的情况下在域控制器上以SYSTEM身份运行恶意代码。Microsoft解释这并不是一个安全漏洞，但它仍然是一个巧妙的技巧，可以用作红队在渗透过程中的AD提权。

### 域管理员-**Domain Admins** <a id="%E5%9F%9F%E7%AE%A1%E7%90%86%E5%91%98-Domain%20Admins"></a>

域管理员组内的成员对域中的域控制器具有完全访问权限。默认情况下，Domain Admins组内的成员是已加入域的所有计算机（包括域控制器）上本地管理组的成员。

Domain Admins组控制对域中所有域控制器的访问，并且可以修改域中所有管理帐户的成员身份。域中的服务管理员组的成员以及企业管理员组的成员拥有对该组的成员的增删改权限

 S-1-5-21-&lt;domain&gt;-1102

![](https://img-blog.csdnimg.cn/20201003145008195.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 企业管理员组-**Enterprise Admins** <a id="%E4%BC%81%E4%B8%9A%E7%AE%A1%E7%90%86%E5%91%98%E7%BB%84-Enterprise%20Admins"></a>

Enterprise Admins组仅存在于Active Directory域林的根域中。如果域处于本机模式，则为通用组。如果域处于混合模式，则它是一个全局组。该组的成员有权在Active Directory中进行林范围的更改，例如添加子域。

[混合模式和本机模式](http://blog.sina.com.cn/s/blog_4bb216ab010008fd.html)

SID/RID: S-1-5-21-&lt;root domain&gt;-519

![](https://img-blog.csdnimg.cn/20201003150536788.png)

默认情况下，该组的唯一成员是林根域的管理员帐户。该组会自动添加到林中每个域的Administrators组中，并提供用于配置所有域控制器的完整访问权限。该组中的成员可以修改所有管理组的成员。成员资格只能由根域中的默认服务管理员组修改。这被认为是服务管理员帐户

![](https://img-blog.csdnimg.cn/20201003160709206.png)

### **事件日志读取组-Event Log Readers** <a id="%E4%BA%8B%E4%BB%B6%E6%97%A5%E5%BF%97%E8%AF%BB%E5%8F%96%E7%BB%84-Event%20Log%20Readers"></a>

该组的成员可以从本地计算机读取事件日志。当服务器提升为域控制器时，将创建该组

SID/RID: S-1-5-32-573

![](https://img-blog.csdnimg.cn/20201003160811315.png)

### **组策略创建者组-Group Policy Creators Owners** <a id="%E7%BB%84%E7%AD%96%E7%95%A5%E5%88%9B%E5%BB%BA%E8%80%85%E7%BB%84-Group%20Policy%20Creators%20Owners"></a>

该组被授权在域中创建，编辑或删除组策略对象。默认情况下，该组的唯一成员是Administrator

SID/RID: S-1-5-&lt;domain&gt;-520

![](https://img-blog.csdnimg.cn/20201003161014376.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

![](https://img-blog.csdnimg.cn/20201003161058914.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### **Hyper-V管理员组-Hyper-V Administrators** <a id="Hyper-V%E7%AE%A1%E7%90%86%E5%91%98%E7%BB%84-Hyper-V%20Administrators"></a>

Hyper-V Administrators组的成员具有对Hyper-V中所有功能的完整且不受限制的访问权限。将成员添加到该组有助于减少管理员组中所需的成员数量，并进一步分隔访问权限

SID/RID: S-1-5-32-578

![](https://img-blog.csdnimg.cn/20201003161131341.png)

**注意：**

在Windows Server 2012之前，对Hyper-V中功能的访问部分受Administrators组成员身份的控制

### windows 2000兼容访问组-**Pre–Windows 2000 Compatible Access** <a id="windows%202000%E5%85%BC%E5%AE%B9%E8%AE%BF%E9%97%AE%E7%BB%84-Pre%E2%80%93Windows%202000%20Compatible%20Access"></a>

Windows 2000以前版本的Compatible Access（兼容的访问）组的成员对域中的所有用户和组具有读取访问权限。提供此组是为了向后兼容运行Windows NT 4.0和更早版本的计算机。默认情况下，特殊标识组“每个人”都是该组的成员。仅当用户运行Windows NT 4.0或更早版本时，才将他们添加到该组

SID/RID: S-1-5-32-554

![](https://img-blog.csdnimg.cn/20201003161315528.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**注意：**

在域控制器成为主要域控制器之前，该组显示为SID，并且它担任操作主机角色（也称为灵活单主机操作或FSMO）。

### **打印操作员组-Print Operators** <a id="%E6%89%93%E5%8D%B0%E6%93%8D%E4%BD%9C%E5%91%98%E7%BB%84-Print%20Operators"></a>

该组的成员可以管理，创建，共享和删除连接到域控制器的打印机。他们还可以管理域中的Active Directory打印机对象。该组的成员拥有可以在本地登录并关闭域中的域控制器的权限。

该组没有默认成员。由于该组的成员可以在域中的所有域控制器上加载和卸载设备驱动程序，因此请谨慎添加用户。该组不能重命名，删除或移动

SID/RID: S-1-5-32-550

![](https://img-blog.csdnimg.cn/20201003161628344.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### **受保护的用户组-Protected Users** <a id="%E5%8F%97%E4%BF%9D%E6%8A%A4%E7%9A%84%E7%94%A8%E6%88%B7%E7%BB%84-Protected%20Users"></a>

在身份验证过程中，受保护的用户组的成员将获得额外的保护，以防止凭据受到损害。

此安全组被设计为有效保护和管理企业内凭据的策略的一部分。该组的成员自动对其帐户应用了不可配置的保护。默认情况下，“受保护的用户”组中的成员资格是限制性的并且是主动保护的。修改帐户保护的唯一方法是从安全组中删除该帐户

SID/RID: S-1-5-21-&lt;domain&gt;-525

  
根据帐户的域功能级别的不同，Windows支持的身份验证方法也做了不同更改，从而进一步保护了“受保护的用户”组的成员。

* "受保护的用户" 组的成员无法使用以下安全支持提供程序进行身份验证： \(Ssp\) ： NTLM、摘要式身份验证或 CredSSP。 密码未缓存在运行 Windows 8.1 或 Windows 10 的设备上，因此当帐户是受保护的用户组的成员时，设备无法对域进行身份验证。
* Kerberos 协议不会在预身份验证过程中使用较弱的 DES 或 RC4 加密类型。 这意味着域必须配置为至少支持 AES 密码套件。
* 无法使用 Kerberos 受限或无约束委派委派用户帐户。 这意味着，如果用户是 "受保护的用户" 组的成员，则以前与其他系统的连接可能会失败。
* 默认的 Kerberos 票证授予票证 \(TGTs "4 小时\) 寿命设置可通过使用身份验证策略和思洛存储器进行配置，可通过 Active Directory 管理中心进行访问。 这意味着，如果超过四个小时，用户必须再次进行身份验证。

![](https://img-blog.csdnimg.cn/20201003161945125.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### **远程桌面用户组-Remote Desktop Users** <a id="%E8%BF%9C%E7%A8%8B%E6%A1%8C%E9%9D%A2%E7%94%A8%E6%88%B7%E7%BB%84-Remote%20Desktop%20Users"></a>

远程桌面用户”组用于授予用户和组权限以远程连接到RD会话主机服务器。该组不能重命名，删除或移动。在域控制器成为主要域控制器之前，在域控制器成为主域控制器并保留操作主机角色 \(也称为灵活单主机操作或 FSMO\) 时，它将显示为 SID。

SID/RID: S-1-5-32-555

![](https://img-blog.csdnimg.cn/20201003163228260.png)

### **架构管理员组-Schema Admins** <a id="%E6%9E%B6%E6%9E%84%E7%AE%A1%E7%90%86%E5%91%98%E7%BB%84-Schema%20Admins"></a>

架构管理员组的成员可以修改Active Directory的架构。该组仅存在于Active Directory域林的根域中。如果域处于纯模式，则为通用组。如果域处于混合模式，则它是一个全局组。

默认情况下，该组的唯一成员是林根域的管理员帐户。该组成员具有对当前域模式的完全管理访问权限。根域中的任何服务管理员组均可修改该组的成员资格。

 SID/RID: S-1-5-&lt;root domain&gt;-518

![](https://img-blog.csdnimg.cn/20201003163812839.png)

### **服务器操作员-Server Operators** <a id="%E6%9C%8D%E5%8A%A1%E5%99%A8%E6%93%8D%E4%BD%9C%E5%91%98-Server%20Operators"></a>

服务器操作员组中的成员可以管理域服务器。该组只存在于域控制器内。默认情况下，该组没有成员。服务器操作员组的成员拥有交互方式登录服务器，创建和删除网络共享资源，启动和停止服务，备份和还原文件，格式化计算机的硬盘驱动器以及关闭计算机的权限。该组不能重命名，删除或移动。

SID/RID: S-1-5-32-549

![](https://img-blog.csdnimg.cn/20201003164211104.png)

**注意：**

默认情况下，此内置组没有成员。服务管理员组，域管理员组以及企业管理员组拥有增删改其成员资格的权限。但该组中的成员不能更改任何管理组成员，同时该组成员拥有可以执行维护任务（例如备份和还原），并且可以更改安装在域控制器上的二进制文件的权限。请注意下列展示的该组用户的默认用户权限。

**默认用户权限**：

1. [允许本地登录](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221980%28v=ws.11%29)：SeInteractiveLogonRight
2. [备份文件和目录](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221961%28v=ws.11%29)：SeBackupPrivilege
3. [更改系统时间](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221970%28v=ws.11%29)：SeSystemTimePrivilege
4. [更改时区](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221986%28v=ws.11%29)：SeTimeZonePrivilege
5. [从远程系统强制关机](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221951%28v=ws.11%29)：SeRemoteShutdownPrivilege
6. [还原文件和目录](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221962%28v=ws.11%29)：SeRestorePrivilege
7. [关闭系统](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221966%28v=ws.11%29)：SeShutdownPrivilege

### WindowsRM远程WMI用户组 <a id="WindowsRM%E8%BF%9C%E7%A8%8BWMI%E7%94%A8%E6%88%B7%E7%BB%84"></a>

S-1-5-21-&lt;domain&gt;-1000

在Windows 8和Windows Server 2012中，“**共享”** 选项卡已添加到“高级安全设置”用户界面。此选项卡显示远程文件共享的安全性属性。要查看此信息，您必须具有以下权限和成员资格，以适合文件服务器正在运行的Windows Server版本。

* 如果文件共享托管在运行操作系统的受支持版本的服务器上：
  * 您必须是WinRMRemoteWMIUsers组或builtin\Administrators组的成员。
  * 您必须具有文件共享的读取权限。
* 如果文件共享托管在运行Windows Server 2012之前的Windows Server版本的服务器上：
  * 您必须是builtin\Administrators组的成员。
  * 您必须具有文件共享的读取权限。

在Windows Server 2012中，访问被拒绝协助功能将Authenticated Users组添加到本地WinRMRemoteWMIUsers组。因此，启用访问拒绝协助功能后，所有对文件共享具有读取权限的经过身份验证的用户都可以查看文件共享权限。

**注意：**

WinRMRemoteWMIUsers\_组允许远程运行Windows PowerShell命令，而[Remote Management Users](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v=ws.11%29?redirectedfrom=MSDN)组通常用于允许用户使用服务器管理器控制台来管理服务器。

## 在计算机上具有特权的Active Directory组 <a id="%E5%9C%A8%E8%AE%A1%E7%AE%97%E6%9C%BA%E4%B8%8A%E5%85%B7%E6%9C%89%E7%89%B9%E6%9D%83%E7%9A%84Active%20Directory%E7%BB%84"></a>

大多数域管会使用组策略将Active Directory组下发到计算机上的本地组\(通常是Administrators组\)中。我们可以使用PowerView来很容易地发现在工作站和服务器上拥有管理权限的AD组

```text
get-netgpogroup  查询当前域GPO策略 gpupdate /force  强制更新当前GPO策略
```

[我们新建一个组策略](https://zhidao.baidu.com/question/1695245005699677948.html)

![](https://img-blog.csdnimg.cn/20201003170951389.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

我们还可以使用PowerView来确定OU对哪些AD组具有计算机管理权限

```text
get-NetComputer -ADSpath 'OU=Domain Controllers,DC=pig,DC=com'
```

![](https://img-blog.csdnimg.cn/20201003172559351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

## **Active Directory对象权限（ACL）** <a id="Active%20Directory%E5%AF%B9%E8%B1%A1%E6%9D%83%E9%99%90%EF%BC%88ACL%EF%BC%89"></a>

与文件系统权限类似，Active Directory对象也具有权限。

这些权限称为访问控制列表（ACL）。在对象上设置的权限使用一种称为[安全描述符定义语言](https://blogs.technet.microsoft.com/askds/2008/04/18/the-security-descriptor-definition-language-of-love-part-1/) [（SDDL](https://msdn.microsoft.com/en-us/library/windows/desktop/dd981030%28v=vs.85%29.aspx)）的加密格式，如下所示：_D:PAI\(D;OICI;FA;;;BG\)\(A;OICI;FA;;;BA\)\(A;OICIIO;FA;;;CO\)\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BU\)_

域内对此进行了图形化翻译，以提供我们习惯使用的更加用户友好的格式（请参见下面的屏幕截图）。

每个Active Directory对象都有在其上配置的权限，可以是明确定义的权限，也可以是从其上方的对象（通常是OU或域）继承的权限，并且可以定义该权限以允许或拒绝该对象及其属性的权限。

在执行[Active Directory安全评估时](https://trimarcsecurity.com/security-services)，我们会扫描Active Directory中的AD ACL，并根据对AD对象（例如域，OU，安全组等）的委派来识别具有特权的帐户/组。

Active Directory中的每个对象都具有默认权限以及继承的权限和任何显式权限。鉴于默认情况下，经过身份验证的用户具有对AD中对象的读取访问权限，因此可以轻松收集其大多数属性以及对该对象，AD对象，其属性和权限定义的权限。

关于AD ACL的简要说明。系统容器中有一个名为“ [AdminSDHolder](https://adsecurity.org/?p=1906) ”的对象，该对象仅具有一个目的：成为域中具有高级别权限的对象（及其成员）的权限模板对象。

受SDProp保护的对象（Windows Server 2008和Windows Server 2008 R2）：

* 账户运营商
* 管理员
* 管理员
* 备份操作员
* 域管理员
* 域控制器
* 企业管理员
* krbtgt
* 打印运营商
* 只读域控制器
* 复制器
* 架构管理员
* 服务器操作员

大约每60分钟，PDC模拟器就会运行一个过程来枚举所有这些受保护的对象及其成员，然后标记在[AdminSDHolder](https://adsecurity.org/?p=1906)对象上配置的权限（并将admin属性设置为“ 1”）。这样可以确保特权组和帐户免受不正确的AD权限委派。

要保持对AD对象的自定义权限非常困难。例如，下图显示了对OU的权限

![](https://img-blog.csdnimg.cn/20201003173757845.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

* 例如这样的ACL就非常的危险

![](https://img-blog.csdnimg.cn/20201003174032498.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

## 攻击者对权限提升感兴趣的ACL包括： <a id="%E6%94%BB%E5%87%BB%E8%80%85%E5%AF%B9%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87%E6%84%9F%E5%85%B4%E8%B6%A3%E7%9A%84ACL%E5%8C%85%E6%8B%AC%EF%BC%9A"></a>

* \*\*\*\*[**复制目录更改**](https://msdn.microsoft.com/en-us/library/ms684355%28v=vs.85%29.aspx)\*\*\*\*

例如DCSync

* **GenericAll**

权限:创建或删除子对象、删除子树、读写属性、检查子对象和对象本身、从目录中添加和删除对象以及具有扩展权限的读写权限。

* **GenericWrite**

读取此对象的权限，写入此对象上的所有属性，并对该对象执行所有经过验证的写入操作的权利。

* **WriteDACL**

提供修改对象安全性的功能，这可能导致对该对象的完全控制。修改对象安全描述符中的DACL的权限。例如Exchange的ACL提权

* **WriteOwner**

提供获得对象所有权的能力。对象的所有者可以[获取对该对象的完全控制权](https://technet.microsoft.com/en-us/library/dd125370%28v=ws.10%29.aspx)。拥有对象所有权的权利。用户必须是对象受托人。用户不能将所有权转让给其他用户。

* **WriteProperty**

通常与特定的属性/属性信息配对。例如：委托服务台组具有修改特定AD对象属性的能力，例如Member（用于修改组成员），显示名称，描述，电话号码等。

* **CreateChild**

提供创建指定类型（或“全部”）对象的功能。

* **DeleteChild**

提供删除指定类型（或“全部”）对象的功能。

[**扩展权限**](https://msdn.microsoft.com/en-us/library/ms683985%28v=vs.85%29.aspx)：这是一个有趣的[**扩展，**](https://msdn.microsoft.com/en-us/library/ms683985%28v=vs.85%29.aspx)因为它提供了超出显而易见的其他权限。示例：对计算机对象的所有扩展权限都[可以提供对LAPS本地管理员密码属性的读取访问权限](https://adsecurity.org/?p=3164)。

在域中创建和链接GPO的能力应被视为有效的Domain Admin权限，因为它提供了修改安全设置，安装软件，配置用户和计算机登录（和启动/关闭）脚本以及运行命令的能力。

* \*\*\*\*[**管理组策略链接**](https://technet.microsoft.com/en-us/library/cc978262.aspx)**（LinkGPO）**

提供将Active Directory中的现有组策略对象链接到定义了权限的域，OU和/或站点的功能。_默认情况下，GPO Creator拥有者拥有此权利。_

* **创建GPO**

默认情况下，AD组“组策略创建者所有者”拥有此权限。可以通过组策略管理控制台（GPMC）委派。

## powerview部分命令 <a id="powerview%E9%83%A8%E5%88%86%E5%91%BD%E4%BB%A4"></a>

```text
Get-NetDomain 获取当前用户所在域的名称Get-NetUser 获取所有用户的详细信息Get-NetDomainController 获取所有域控制器的信息Get-NetComputer 获取域内所有机器的详细信息Get-NetPrinter 获取域中所有当前计算机对象的数组Get-NetOU 获取域内的OU信息Get-NetGroup 获取所有域内组和组成员的信息Get-NetGroupMember 获取指定域组中所有当前用户的列表Get-NetFileServer 根据SPN获取当前域使用的文件服务器信息Get-NetShare 获取当前域内所有的网络共享信息Get-DFSshare 获取域上所有分发文件系统共享的列表Get-NetSubnet 获取域的其他网段Get-NetSite 获取域内的当前站点Get-NetDomainTrust 获取当前用户域的所有信任Get-NetForestTrust 获取与当前用户的域关联的林的所有信任Find-ForeignUser 枚举在其主域之外的组中的用户Find-ForeignGroup 枚举域组的所有成员并查找查询域之外的用户Invoke-MapDomainTrust 尝试构建所有域信任的关系映射Get-NetLoggedon 获取主动登录到指定服务器的用户Get-NetLocalGroup 获取一个或多个远程主机上本地组的成员Get-NetSession 获取指定服务器的会话Get-NetRDPSession 获取指定服务器的远程连接Get-NetProcess 获取远程主机的进程Get-UserEvent 获取指定用户的日志Get-ADObject 获取活动目录的对象Get-NetGPO 获取域内所有的组策略对象Get-NetGPOGroup 获取域中设置”受限组”的所有GPOFind-GPOLocation 获取用户/组，并通过GPO枚举和关联使其具有有效权限的计算机Find-GPOComputerAdmin 获取计算机并通过GPO枚举确定谁对其具有管理权限Get-DomainPolicy 获取域默认策略或域控制器策略Get-DomainSID 返回指定域的SIDInvoke-UserHunter 获取域用户登录的计算机信息及该用户是否有本地管理员权限Invoke-ProcessHunter 通过查询域内所有的机器进程找到特定用户Invoke-UserEventHunter 根据用户日志查询某域用户登陆过哪些域机器Invoke-ShareFinder 在本地域中的主机上查找（非标准）共享Invoke-FileFinder 在本地域中的主机上查找潜在的敏感文件Find-LocalAdminAccess 在域上查找当前用户具有本地管理员访问权限的计算机Find-ManagedSecurityGroups 搜索受管理的活动目录安全组并标识对其具有写访问权限的用户，即这些组拥有添加或删除成员的能力Get-ExploitableSystem 发现系统可能易受常见攻击Invoke-EnumerateLocalAdmin 枚举域中所有计算机上本地管理员组的成员
```

### 利用漏洞 <a id="%E5%88%A9%E7%94%A8%E6%BC%8F%E6%B4%9E"></a>

### SID历史记录-**SIDHistory** <a id="SID%E5%8E%86%E5%8F%B2%E8%AE%B0%E5%BD%95-SIDHistory"></a>

[SID历史记录](https://msdn.microsoft.com/en-us/library/ms679833%28v=vs.85%29.aspx)是支持[迁移方案](https://technet.microsoft.com/en-us/library/cc779590%28v=ws.10%29.aspx)的属性。每个用户帐户都有一个关联的[安全标识符（SID）](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379571%28v=vs.85%29.aspx)，用于跟踪安全主体以及该帐户在连接到资源时所具有的访问权限。SID历史记录使对另一个帐户的访问可以有效地克隆到另一个帐户。这对于确保用户从一个域移动（迁移）到另一个域时保留访问权限非常有用。由于在创建新帐户时用户的SID会更改，因此旧SID需要映射到新帐户。将域A中的用户迁移到域B时，将在域B中创建一个新的用户帐户，并且将域A用户的SID添加到域B用户帐户的SID历史记录属性中。这样可以确保DomainB用户仍然可以访问DomainA中的资源。

这意味着，如果一个帐户在其SIDHistory属性中具有特权帐户或组，则[该帐户将获得分配给这些帐户或组的所有权限，无论是直接还是间接分配的权限](https://adsecurity.org/?p=1772)。如果攻击者获得了该帐户的控制权，则他们拥有所有关联的权利。通过SIDHistory中的SID提供的权利可能不明显，因此会丢失。

### **组策略权限-Group Policy Permissions** <a id="%E7%BB%84%E7%AD%96%E7%95%A5%E6%9D%83%E9%99%90-Group%20Policy%20Permissions"></a>

组策略对象（GPO）是在Active Directory中创建，配置和链接的。当GPO链接到OU时，GPO中的设置将应用于该OU中的适当对象（用户/计算机）。

可以配置GPO的权限，以将GPO修改权限委派给任何安全主体。

如果在链接到域的组策略上配置了自定义权限，并且攻击者获得了具有修改访问权限的帐户的访问权限，则该域可能会受到威胁。攻击者修改GPO设置以运行代码或安装恶意软件。此访问级别的影响取决于GPO的链接位置。如果GPO链接到域或域控制器容器，则它们拥有该域。如果GPO链接到工作站或服务器OU，则影响可能会有所减少；但是，由于能够在所有工作站或服务器上运行代码，因此可能仍会损害域。

扫描GPO权限可以确定哪些GPO的权限不当，扫描GPO链接的位置可以确定影响。

有趣的事实：组策略的创建者保留对GPO的修改权限。可能的结果是，域管理员需要为域设置审核策略，但是发现OU管理员已经使用所需设置创建了GPO。因此，域管理员将此GPO链接到域根，该根将设置应用于域中的所有计算机。问题是，如果此OU管理员帐户遭到破坏，则OU管理员仍可以修改现在链接到域根目录的GPO，从而提供升级路径。

[Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) 提供了一种快速方法来扫描所有域GPO的所有权限：

```text
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
```

![](https://img-blog.csdnimg.cn/20201003175617699.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

#### 参考：[滥用GPO权限](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/) <a id="%E5%8F%82%E8%80%83%EF%BC%9A%E6%BB%A5%E7%94%A8GPO%E6%9D%83%E9%99%90"></a>

**用户权限分配**

[用户权限分配](https://technet.microsoft.com/en-us/library/bb457125.aspx)通常在计算机GPO中进行配置，并定义了计算机的多个权限。

通常在应用于域控制器容器的默认域控制器策略中使用用户权限分配来配置域控制器。解析链接到域控制器的GPO，可以提供有关具有增加的DC和域权限的安全主体的有用信息。

[这些任务包括](https://technet.microsoft.com/en-us/library/bb457125.aspx)：

* SeTrustedCredManAccessPrivilege：作为受信任的呼叫者访问凭据管理器
* SeNetworkLogonRight：从网络访问此计算机
* SeTcbPrivilege：作为操作系统的一部分
* SeMachineAccountPrivilege：将工作站添加到域
* SeIncreaseQuotaPrivilege：调整进程的内存配额
* SeInteractiveLogonRight：允许本地登录
* SeRemoteInteractiveLogonRight：允许通过远程桌面服务登录
* SeBackupPrivilege：备份文件和目录
* SeChangeNotifyPrivilege：绕过遍历检查
* SeSystemtimePrivilege：更改系统时间
* SeTimeZonePrivilege：更改时区
* SeCreatePagefilePrivilege：创建页面文件
* SeCreateTokenPrivilege：创建令牌对象
* SeCreateGlobalPrivilege：创建全局对象
* SeCreatePermanentPrivilege：创建永久共享对象
* SeCreateSymbolicLinkPrivilege：创建符号链接
* SeDebugPrivilege：调试程序
* SeDenyNetworkLogonRight：拒绝从网络访问此计算机
* SeDenyBatchLogonRight：拒绝作为批处理作业登录
* SeDenyServiceLogonRight：拒绝作为服务登录
* SeDenyInteractiveLogonRight：拒绝本地登录
* SeDenyRemoteInteractiveLogonRight：拒绝通过远程桌面服务登录
* SeEnableDelegationPrivilege：使计算机和用户帐户受信任进行委派
* SeRemoteShutdownPrivilege：从远程系统强制关闭
* SeAuditPrivilege：生成安全审核
* SeImpersonatePrivilege：身份验证后模拟客户端
* SeIncreaseWorkingSetPrivilege：增加流程工作集
* SeIncreaseBasePriorityPrivilege：增加调度优先级
* SeLoadDriverPrivilege：加载和卸载设备驱动程序
* SeLockMemoryPrivilege：锁定内存中的页面
* SeBatchLogonRight：作为批处理作业登录
* SeServiceLogonRight：作为服务登录
* SeSecurityPrivilege：管理审核和安全日志
* SeRelabelPrivilege：修改对象标签
* SeSystemEnvironmentPrivilege：修改固件环境值
* SeManageVolumePrivilege：执行卷维护任务
* SeProfileSingleProcessPrivilege：配置文件单个进程
* SeSystemProfilePrivilege：分析系统性能
* SeUndockPrivilege：从扩展坞中卸下计算机
* SeAssignPrimaryTokenPrivilege：替换流程级别令牌
* SeRestorePrivilege：还原文件和目录
* SeShutdownPrivilege：关闭系统
* SeSyncAgentPrivilege：同步目录服务数据
* SeTakeOwnershipPrivilege：取得文件或其他对象的所有权

此列表中有趣的（特别是在适用于域控制器的GPO中）：

* [允许本地登录](https://technet.microsoft.com/en-us/library/dn221980%28v=ws.11%29.aspx)和[允许通过远程桌面服务](https://technet.microsoft.com/en-us/library/dn221985%28v=ws.11%29.aspx)登录（[Allow logon locally](https://technet.microsoft.com/en-us/library/dn221980%28v=ws.11%29.aspx) & [Allow logon over Remote Desktop Services](https://technet.microsoft.com/en-us/library/dn221985%28v=ws.11%29.aspx)）：提供登录权限。
* [管理审核和安全日志](https://technet.microsoft.com/en-us/library/cc957161.aspx)（[Manage auditing and security log](https://technet.microsoft.com/en-us/library/cc957161.aspx)）：提供查看事件日志中的所有事件（包括安全事件）并清除事件日志的功能。 有趣的事实：Exchange服务器需要此权限，这意味着如果攻击者获得了Exchange服务器上的系统权限，则它们可以清除域控制器安全日志。
* [同步目录服务数据](https://technet.microsoft.com/en-us/library/dn221988%28v=ws.11%29.aspx)（[Synchronize directory service data](https://technet.microsoft.com/en-us/library/dn221988%28v=ws.11%29.aspx)）：“此策略设置确定哪些用户和组有权同步所有目录服务数据，而不受对象和属性的保护。使用LDAP目录同步（dirsync）服务需要此特权。域控制器固有地具有此用户权限，因为同步过程在域控制器上的系统帐户的上下文中运行。” 这意味着在域控制器上具有此用户权限的acocunt可能能够运行[DCSync](https://adsecurity.org/?p=1729)。
* [使计算机和用户帐户的委派受到信任](https://technet.microsoft.com/en-us/library/dn221977%28v=ws.11%29.aspx)（[Enable computer and user accounts to be trusted for delegation](https://technet.microsoft.com/en-us/library/dn221977%28v=ws.11%29.aspx)）：提供在域中的计算机和用户上配置委派的功能。 有趣的事实：这提供了在计算机或用户帐户上设置[Kerberos委派的](https://adsecurity.org/?p=1667)功能。
* [身份验证后模拟客户端](https://technet.microsoft.com/en-us/library/dn221967%28v=ws.11%29.aspx)（[Impersonate a client after authentication](https://technet.microsoft.com/en-us/library/dn221967%28v=ws.11%29.aspx)）：这个[客户端](https://technet.microsoft.com/en-us/library/dn221967%28v=ws.11%29.aspx)看起来很有趣……
* [拥有文件或其他对象的所有权](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)（[Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)）：仅管理员。“具有“ 拥有文件或其他对象的所有权”用户权限 的任何用户都可以控制任何对象，而无需考虑对该对象的权限，然后对他们对该对象进行任何更改。此类更改可能导致数据泄露，数据损坏或拒绝服务情况。”
* [加载和卸载设备驱动程序](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)（[Load and Unload Device Drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)）：“设备驱动程序作为高特权代码运行。具有“加载和卸载设备驱动程序”用户权限的用户可能无意中安装了伪装成设备驱动程序的恶意软件。管理员应格外小心，仅安装具有经过验证的数字签名的驱动程序。”

## 总结 <a id="%E6%80%BB%E7%BB%93"></a>

为了有效地识别具有特权访问权限的所有帐户，最重要的是确保在探索域内所有用户的过程中有效地识别权限。这意味着防御者需要检查对AD对象的许可，从组织单位（OU）开始，然后分支到安全组。

检查事项：

* 枚举默认组（包括子组）的组成员身份。确定所需的权利，然后删除其他权利。
* 扫描Active Directory（特别是OU和安全组）以进行自定义委派。
* 扫描具有SIDHistory的帐户（仅在从一个域到另一个域的活动迁移期间才需要）。
* 查看适用于域控制器，服务器和工作站的GPO中的用户权限分配。
* 查看将AD组添加到本地组的GPO，并确保仍然需要这些GPO，并且权限级别适当。

用于检查Active Directory权限的工具：

* [Bloodhound](https://github.com/BloodHoundAD/BloodHound)
* [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) \(modules used in Bloodhound\)
* [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/)

