# DCSync：攻击与检测

## 讲在前面： <a id="%E8%AE%B2%E5%9C%A8%E5%89%8D%E9%9D%A2%EF%BC%9A"></a>

Mimkatz在2015年8月添加的一个主要特性是“DCSync”，它可以有效地“模拟”一个域控制器，并向目标域控制器请求帐户密码数据。DCSync由Benjamin Delpy和Vincent Le Toux编写。

使用适当的权限来利用Mimikatz的DCSync，攻击者可以通过网络从域控制器获取密码hash和以前的密码hash，从而不需要进行交互式的登录或复制Active Directory数据库文件\(ntdd .dit\)来得到密码hash

运行DCSync需要特殊权限。管理员、域管理员、企业管理员以及域控制器计算机帐户的任何成员都可以运行DCSync来提取密码数据。注意，默认情况下，只读域控制器不允许为用户提取密码数据。攻击者可以使用它来获取任何帐户的NTLM哈希，包括KRBTGT帐户，从而使攻击者可以创建[Golden Tickets](https://blog.stealthbits.com/complete-domain-compromise-with-golden-tickets/)。该攻击最棘手的部分是它利用了Active Directory的有效和必要功能，因此无法将其关闭或禁用

```text
lsadump::dcsync /domain:pingpig.com /user:krbtgt
```

![](https://img-blog.csdnimg.cn/20201003011143756.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

上图中的凭据部分显示了当前的NTLM哈希以及密码历史记录。此信息可能对攻击者有价值，因为它可以为用户（如果被破解）提供密码创建策略

[**有关红队使用Mimikatz DCSync的帮助信息**](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)

## **DCSync的工作方式：** <a id="DCSync%E7%9A%84%E5%B7%A5%E4%BD%9C%E6%96%B9%E5%BC%8F%EF%BC%9A"></a>

一般来说，DCSYNC攻击的工作方式如下：

1. 发现域控制器以请求复制。
2. 使用[GetNCChanges](https://wiki.samba.org/index.php/DRSUAPI) 函数请求用户复制 。
3. DC将复制数据（包括密码哈希）返回给请求者。

 GetNCChanges函数的简介：

当第一个客户端DC要从第二个客户端获取AD对象更新时，客户端DC向服务器发送DSGetNCChanges请求。该响应包含一组客户端必须应用于其NC副本的更新。

对于仅一个响应消息，更新集可能太大。在这些情况下，将完成多个DSGetNCChanges请求和响应。此过程称为复制周期或简称为循环。

## 利用DCsync <a id="%E5%88%A9%E7%94%A8DCsync"></a>

1. 打开“ Active Directory用户和计算机”管理中心
2. 右键单击域对象，例如“ company.com”，然后右击“属性”。
3. 在“安全性”选项卡上，如果未列出所需的用户帐户，请单击“添加”。如果列出了所需的用户帐户，请继续执行步骤7。
4. 在“选择用户，计算机或组”对话框中，选择所需的用户帐户，然后单击“添加”。
5. 单击确定以返回到属性对话框。
6. 单击所需的用户帐户。
7. 单击以选中列表中指定的属性的复选框。
8. 单击“应用”，然后单击“确定”。
9. 关闭管理单元。

![](https://img-blog.csdnimg.cn/20201003013423410.png)![](https://img-blog.csdnimg.cn/20201003013445143.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

![](https://img-blog.csdnimg.cn/20201003013516261.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

可以使用常规域用户帐户运行DCSync。但需要在域控上委派以下三种权限，域用户帐户可才以使用DCSync成功检索密码数据：

* **复制目录更改（DS-Replication-Get-Changes）**

需要扩展权限，以便仅复制来自给定NC的那些更改，这些更改也已复制到全局编录（不包括秘密域数据）。此约束仅对域NC有意义。

* **全部复制目录更改（DS-Replication-Get-Changes-All）**

控制访问权限，该权限允许复制给定复制NC中的所有数据，包括秘密域数据。

* **复制过滤集中的目录更改（极少出现，仅在某些环境中需要）**

**注意：**

默认情况下，Administrators和Domain Controller组的成员具有这些权限。域中的“完全控制”权限也提供了这些权限，请限制域内用户具有域管理员级别的权限。

### 使用DCSync提取krbtgt账户的密码数据 <a id="%E4%BD%BF%E7%94%A8DCSync%E6%8F%90%E5%8F%96krbtgt%E8%B4%A6%E6%88%B7%E7%9A%84%E5%AF%86%E7%A0%81%E6%95%B0%E6%8D%AE"></a>

```text
lsadump::dcsync /domain:pingpig.com /user:krbtgt
```

![](https://img-blog.csdnimg.cn/20201003011143756.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

### 导出域内所有用户的hash：

```text
lsadump::dcsync /domain:pingpig.com /all /csv
```

![](https://img-blog.csdnimg.cn/20201003014030760.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

## 监测DCSync的使用 <a id="%E7%9B%91%E6%B5%8BDCSync%E7%9A%84%E4%BD%BF%E7%94%A8"></a>

虽然可以使用安全事件日志识别DCSync的使用情况，但最好的检测方法是通过网络监视

### **启用网络监控**

网络监控是最好的检测方法。应标识所有域控制器IP地址，然后将其添加到“复制允许列表”中。企业应配置入侵检测系统（IDS），以在发现DSGetNCChange请求源自该IP列表之外时发出警报，

### **审核域管理员和用户权限**

要防止DCSync攻击，需要了解哪些帐户具有域复制权限。有了这些基本知识，安全人员才好判断是撤销或限制域内任何一个帐户的某些权利。鉴于这些特权是域管理员和域控制器的标准权限，请考虑严格限制对这些组的访问，同时还要加强所有组成员的身份验证要求，以使离线密码破解更加困难。

### **加强补丁和配置管理**

确保遵循基本的安全防御习惯，包括补丁和配置管理，端点检测和响应以及用户意识培训。基本的安全防护才是保护帐户免受外部攻击者或内部恶意人员攻击的最可靠方法。

