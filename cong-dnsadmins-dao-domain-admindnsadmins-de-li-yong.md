# 从DNSAdmins到Domain Admin-DNSAdmins的利用

两篇十分优秀的论文：

* [https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
* [http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html ](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

第一个帖子解释了如何在域控制器上以系统身份执行DLL的情况，前提是该帐户是DNSAdmins的成员。  
内容大致如下：

除了实现自己的DNS服务器之外，Microsoft还为该服务器实现了自己的管理协议，以简化管理并与Active Directory域集成。默认情况下，域控制器也是DNS服务器。DNS服务器需要几乎每个域用户都可以访问和使用。反过来，这又暴露了域控制器上的某些攻击面-一方面是DNS协议本身，另一方面是基于RPC的管理协议。协议中的某些**功能在某些情况下允许我们在域控制器上以SYSTEM身份运行代码，而无需成为域管理员**。正如Microsoft确认的那样，尽管这并不算一个安全漏洞，但它仍然是一个非常棒的技巧，可以用作红队参与中的AD权限提升

**发行摘要**

* DNS管理通过RPC执行（UUID为50ABC2A4–574D-40B3–9D66-EE4FD5FBA076），传输机制为\ PIPE \ DNSSERVER命名管道。
* 根据Microsoft协议规范，“ ServerLevelPluginDll”操作使我们能够加载我们选择的dll（无需验证dll路径）。
* dnscmd.exe已实现此选项： _dnscmd.exe / config / serverlevelplugindll \\ path \ to \ dll_
* 当作为DNSAdmins成员的用户执行此dnscmd.exe命令时，将填充以下注册表项： _HKEY\_LOCAL\_MACHINE \ SYSTEM \ CurrentControlSet \ services \ DNS \ Parameters \ ServerLevelPluginDll_
* 重新启动DNS服务将在此路径中加载DLL。但是，DLL需要包含“ DnsPluginInitialize，DnsPluginCleanup或DnsPluginQuery导出之一。”
* 因此，Shay介绍了如何修改DLL以便正确加载并允许DNS服务成功启动。
* 只需在域控制器的计算机帐户可以访问的网络共享上提供DLL。

[Mimikatz](https://adsecurity.org/?page_id=1821)包含一个可以自定义的DLL（因为[GitHub上](https://github.com/gentilkiwi/mimikatz)的[源代码](https://github.com/gentilkiwi/mimikatz)），因此可以在DNS服务启动时更新要加载的Mimikatz DLL，并监视凭据并将其转储到攻击者具有的位置访问。

此外，Shay指出，不需要DNSAdmins组成员身份。如果该帐户具有对DNS服务器对象的写访问权限，则可以成功执行这些步骤。

Shay注意到这已报告给Microsoft：

_已就此问题与Microsoft的MSRC联系，并声明将通过仅允许DC管理员更改ServerLevelPluginDll注册表项来解决此问题，并且可以在以后的版本中关闭此功能。_

**减轻**

* 确保只有管理员帐户是DNSAdmins组的成员，并确保它们仅从管理系统管理DNS。在仔细检查成员资格的组列表中包括DNSAdmins。
* 定期检查DNS服务器对象的权限，以了解任何不应具有特权访问权限的组/帐户。
* 将RPC与DC的通信限制为仅管理子网。

