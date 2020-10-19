# Microsoft KB2871997的学习



## 讲在前面

2014年，Microsoft发布了KB2871997补丁，它主要囊括了Windows 8.1和Windows Server 2012 R2中增强的安全保护机制。所以，以往的例如：Windows 7，Windows 8，Windows Server 2008R2和Windows Server 2012也可以更新该补丁后获得上述安全保护机制。

## 介绍

增强的安全保护机制中有如下部分几点：  


* 减少存储在内存中的凭据数据
* 支持现代身份验证（Kerberos AES）

其实主要防范的是在身份登录时凭据存储的泄露问题，目前windows主要有两种登录类型：

## 交互式登录

> 用户在登录提示窗口输入凭据进行登录的过程就是交互式登录（一般出现在远程桌面协议RDP服务或连接其他服务时）。这种登录类型的凭据存储在内存中，通常以各种形式例如：Kerberos票据、NTLM-Hash、LM-Hash（如果密码小于15个字符），甚至存储明文密码。
>
> 注意：  
>
>
> Mimikatz可以在LASS保护中提取内存中的凭据，也可以在本地Windows安全账户管理器\(SAM\)中提取凭据

## 网络式登录

> 此登陆方式发生在用户、服务或计算机身份验证之后，才能使用。例如在对域内某个服务发起请求时，主机会将存储在本地的Hash发送给服务进行验证。此类登录不会将票据发送至目标服务，但却会留下Hash，所以也就产生了“哈希传递”这个攻击技巧。

注意

该补丁无法阻止”哈希传递“的攻击方式，但其确实有助于是Windows免受一些常见的攻击，例如：明文密码脱取、RDP凭据盗取、盗取本地Administrator账户进行横向移动。  


## KB2871997囊括的几个重要保护如下：

### **受保护的用户组支持**（强制Kerberos身份验证以实施AES加密）

* 当“域功能级别”设置为Windows Server 2012 R2时，将创建“受保护的用户”组。
* 受保护的用户组中的帐户只能使用Kerberos协议进行身份验证，拒绝NTLM，摘要式身份验证和CredSSP。
* Kerberos拒绝DES和RC4加密类型进行预身份验证-必须将域配置为支持AES或更高版本。
* 不能使用Kerberos约束或不受约束的委托来委托受保护用户的帐户。
* 受保护的用户可以使用“[身份验证策略](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn486813%28v=ws.11%29?redirectedfrom=MSDN)”很好地工作。

### **受限管理员RDP模式远程桌面客户端支持（mstsc / RestrictedAdmin）**

* 受限Admin RDP模式增强了安全性，可以保护管理员凭据–该模式不适用于用户（“远程桌面用户”）。

> 在此更新之前，RDP登录是一种交互式登录，只有在用户提供用户名和密码之后才可以访问。以这种方式登录到RDP主机时，会将用户凭据放置在RDP主机的内存中，如果主机受到威胁，它们可能会被窃取。此更新使RDP支持网络登录，其中可以传递用户现有登录令牌以进行RDP访问的身份验证。使用此登录类型可确保RDP服务器上不存储用户的凭据。从而保护凭据

* Microsoft建议在服务台用户RDP到工作站以解决问题的情况下利用“受限管理员”功能，以确保不在工作站上存储用户的凭据（这要求工作站为Windows 8.1或更高版本）。
* 该补丁不会将“受限管理RDP”**服务器**模式反向移植到Windows 8.1和Windows Server 2012 R2之前的操作系统。 

### **通过哈希增强保护**

* **注销时删除凭证**
  * 用户登录时，Windows将用户凭据（纯文本密码，NTLM密码哈希，Kerberos TGT /会话密钥）缓存在内存（LSASS进程）中。注销时，应从内存中清除这些凭据，但这并非总是如此。该补丁可确保注销后清除凭据。
* **新的SID**
  * LOCAL\_ACCOUNT（S-1-5-113）–任何本地帐户
  * LOCAL\_ACCOUNT\_AND\_MEMBER\_OF\_ADMINISTRATORS\_GROUP（S-1-5-114）–属于管理员组成员的任何本地帐户。
  * 使用“拒绝从网络访问此计算机”和“拒绝通过远程桌面服务登录”设置在组策略中配置新的知名SID，可以防止本地帐户通过网络连接。

### **从LSASS删除明文凭证**

* 由于兼容性原因，默认情况下禁用。明文密码存储在内存（LSASS）中，主要支持WDigest身份验证。
* [启用此功能可防止将明文凭证存储在内存（LSASS）中。](http://support.microsoft.com/kb/2871997)
* 通过将位于以下位置的注册表项“ UseLogonCredential”设置为“ 0”（双字）来启用此功能： HKEY\_LOCAL\_MACHINE \ SYSTEM \ CurrentControlSet \ Control \ SecurityProviders \ WDigest“ UseLogonCredential” 在Windows 8.1 / Windows 2012 R2上，此值设置为0（摘要式身份验证已禁用）。该修补程序将Windows的早期版本中的值设置为1，以实现向后兼容（启用摘要式身份验证）。 [![WDIGEST-RegistryKey-UseLogonCredential-1](https://img-blog.csdnimg.cn/img_convert/6b839e5ba3772ec4d358b7723fd566fd.png)](https://adsecurity.org/wp-content/uploads/2015/09/WDIGEST-RegistryKey-UseLogonCredential-1.jpg)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​
* NT哈希和Kerberos密钥仍存储在内存（LSASS）中。
* 检查域控制器（事件ID 4776）和所有服务器（事件ID 4624）上的事件日志，以确定WDigest（摘要式身份验证）是否仍在使用。查找“身份验证程序包：WDigest（摘要式身份验证）”。

