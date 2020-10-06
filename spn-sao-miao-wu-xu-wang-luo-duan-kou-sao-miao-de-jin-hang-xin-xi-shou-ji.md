# SPN扫描–无需网络端口扫描的进行信息收集

## 讲在前面

在Active Directory环境中发现服务的最佳方法是通过所谓的“ SPN扫描”。攻击者进行SPN扫描的主要好处是，SPN扫描不需要连接到域内网络上的每个IP即可检查服务端口。SPN扫描通过对域控制器的LDAP查询执行服务发现。由于SPN查询是正常Kerberos票证行为的一部分，因此即使是攻击者，检测也很难发现是善意还是恶意的查询，而netowkr端口扫描非常明显。

发现利用Kerberos身份验证的服务时需要服务主体名称（SPN: Service Principal Names）

### 简介SPN的知识点： <a id="%E7%AE%80%E4%BB%8BSPN%E7%9A%84%E7%9F%A5%E8%AF%86%E7%82%B9%EF%BC%9A"></a>

SPN 是服务使用 Kerberos 身份认证协议在网络上的唯一标识符，它由服务类、主机名和端口组成。在使用 Kerberos 身份认证的网络中，必须在内置计算机帐户（如 NetworkService 或 LocalSystem）或用户帐户下为服务器注册 SPN。对于内置帐户，SPN 将自动进行注册。但是，如果在域用户帐户下运行服务，则必须要使用其帐户手动注册SPN，一个用户账户下可以有多个SPN，但一个SPN只能注册到一个账户

我们处于Active Directory环境中。要了解什么是SPN，我们必须了解Active Directory中的服务概念是什么。服务实际上是一种功能，一种软件，可以由AD（Active Directory）的其他成员使用。例如，你可以拥有Web服务器，网络共享，DNS服务，打印服务等。要识别服务，我们至少需要知道两件事。相同的服务可以在不同的主机上运行，​​因此我们需要指定**host**，而计算机可以承载多个服务，因此显然需要指定**service**。

#### SPN命名实例 <a id="SPN%E5%91%BD%E5%90%8D%E5%AE%9E%E4%BE%8B"></a>

* **MSSQLSvc / &lt;FQDN&gt;：\[&lt;端口&gt; \| &lt;instancename&gt;\]**，其中：
  * **MSSQLSvc**是正在注册的服务。
  * **&lt;FQDN&gt;**是服务器的标准域名。
  * **&lt;port&gt;**是TCP端口号。
  * **&lt;instancename&gt;**是SQL Server实例的名称。

![](https://img-blog.csdnimg.cn/20201002200739396.png)

#### SPN默认实例 <a id="SPN%E9%BB%98%E8%AE%A4%E5%AE%9E%E4%BE%8B"></a>

* **MSSQLSvc / &lt;FQDN&gt;：&lt;端口&gt;** \| **MSSQLSvc / &lt;FQDN&gt;**，其中：
  * **MSSQLSvc**是正在注册的服务。
  * **&lt;FQDN&gt;**是服务器的标准域名。
  * **&lt;port&gt;**是TCP端口号。

![](https://img-blog.csdnimg.cn/20201002200739396.png)

**注意:**新的SPN格式不需要端口号。这意味着多端口服务器或不使用端口号的协议可以使用Kerberos身份验证。

![](https://img-blog.csdnimg.cn/20201002200807582.png)

| MSSQLSvc/&lt;服务器的标准域名&gt;:&lt;TCP端口&gt; | 使用TCP时，提供程序生成的默认SPN。&lt;port&gt;是一个TCP端口号 |
| :--- | :--- |
| MSSQLSvc/&lt;服务器的标准域名&gt; | 当使用TCP以外的协议时，提供程序为默认实例提供的默认SPN。&lt;FQDN&gt;是完全限定的域名。 |
| MSSQLSvc/&lt;服务器的标准域名&gt;:&lt;实例的名称&gt; | 当使用TCP以外的协议时，提供商为命名实例生成的默认SPN。&lt;instancename&gt;是MSSQLSvc实例的名称。 |

![](https://img-blog.csdnimg.cn/20201002201225955.png)

![](https://img-blog.csdnimg.cn/20201002201238429.png)

![](https://img-blog.csdnimg.cn/20201002201426129.png)

### 部分查询SPN脚本 <a id="%E9%83%A8%E5%88%86%E6%9F%A5%E8%AF%A2SPN%E8%84%9A%E6%9C%AC"></a>

**注意：域内普通用户可以查询，但只有域管理权限才可以增改删SPN**

### **windows自带setspn.exe，部分命令如下：**

> **`查看当前域内所有的SPN：setspn -q */*`**
>
> **`查看指定域pig.com注册的SPN：setspn -T pig.com -q */*   如果指定域不存在，则默认切换到查找本域的SPN`**
>
> **`查找本域内重复的SPN：setspn -X`**
>
> **`删除指定SPN：setspn -D MSSQLSvc/WIN-6IKRAED2RMI.pig.com:hello Administrator   需要域管理员权限`**
>
> **`查找指定用户/主机名注册的SPN：setspn -L username/hostname`**
>
> **`在指定账户或主机名下注册SPN: setspn -U -A VNC/DC1.test.com Administrator     需要域管理员权限`**

**`查看当前域内所有的SPN：setspn -q */*`**

![](https://img-blog.csdnimg.cn/20201002202706428.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**`查看指定域pig.com注册的SPN：setspn -T pig.com -q */*`**

![](https://img-blog.csdnimg.cn/20201002202736422.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**`查找本域内重复的SPN：setspn -X`**

![](https://img-blog.csdnimg.cn/2020100220275766.png)

**`删除指定SPN：setspn -D MSSQLSvc/WIN-6IKRAED2RMI.pig.com:hello Administrator`** 

![](https://img-blog.csdnimg.cn/20201002202938212.png)

**`查找指定用户注册的SPN：setspn -L username`**

![](https://img-blog.csdnimg.cn/20201002203142270.png)

**`查找指定主机名注册的SPN：setspn -L hostname`**

![](https://img-blog.csdnimg.cn/2020100220315794.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**`在指定账户或主机名下注册SPN: setspn -U -A VNC/DC1.test.com Administrator`** 

![](https://img-blog.csdnimg.cn/20201002203218130.png)

### [GetUserSPNs.ps1](https://github.com/nidem/kerberoast)

![](https://img-blog.csdnimg.cn/20201002204431714.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### [GetUserSPNs.vbs](https://github.com/nidem/kerberoast)

![](https://img-blog.csdnimg.cn/20201002204520578.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

![](https://img-blog.csdnimg.cn/20201002204941587.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 总结： <a id="%E6%80%BB%E7%BB%93%EF%BC%9A"></a>

在实战中，我们可以通过SPN扫描，避免内网中的某些防火墙的检测。望各位结合实战环境和自己的偏好进行使用，当然impacket和Empire的工具集内已集成了收集SPN的脚本和模块，您可以深入研究其用法。

