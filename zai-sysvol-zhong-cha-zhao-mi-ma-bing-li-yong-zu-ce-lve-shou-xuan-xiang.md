# 在SYSVOL中查找密码并利用组策略首选项

## 讲在前面：

这是一个在现在看来很古老的渗透手段了，但却是十分有效的一个使攻击者从域用户提权到域管理员的方式之一

在我们所使用的每台Windows计算机内都有一个内置的Administrator账户和密码。大多数域管理员在建设企业内部网络安全制度时，会优先将更改自己本机管理员密码的要求作为必要制度，一种标准的方法是编辑域内组策略下发到所有域内机器上统一更密码，但是这样会造成所有计算机都使用同一个密码的尴尬，所以如果有管理员因为图省事使用组策略进行更改密码的话，我们在渗透上就会事半功倍了。

## **SYSVOL**

**简介：**

我们可以尝试寻找SYSVOL以获取凭证，SYSVOL是Active Directory中的域范围共享，所有经过身份验证的用户都对其具有读访问权。SYSVOL包含登录脚本、组策略数据和其他域范围的数据，这些数据需要在有域控制器的任何地方都可用\(因为SYSVOL自动同步并在所有域控制器之间共享\)。

> 域内组策略存放地：\\&lt;DOMAIN&gt;\SYSVOL\&lt;DOMAIN&gt;\Policies\

![](https://img-blog.csdnimg.cn/20201004160912357.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

#### **已有的问题：**

在实际环境中，企业安全人员面临的挑战之一就是如何保护企业内部所有Windows计算机上的本地管理员账户（RID 500）,目前几乎没有产品会帮助管理员处理到这一点，所以管理员会使用相对传统的办法，使用微软官方的vbs脚本来自定义密码后同统一修改，但这个问题就很鸡肋，一旦攻击者进入内网，搜寻管理员下发的修改密码组策略发现了该vbs脚本，那么游戏就直接结束了。

#### **注意：**

按照目前的实际情况来看，我们不建议使用vbs来进行统一修改域内主机密码的操作，当然排除修改较多的工作站及服务器时，对待用户可以定义在加入域时让其主动修改密码的策略。

![](https://img-blog.csdnimg.cn/20201004162855354.png)

## **组策略首选项-**Group Policy Preferences

该功能的发布对管理员是非常有用的，因为它为以前需要自定义解决方案（例如脚本）的内容提供了一种自动机制。它提供了有用的功能，可以利用组策略以显式凭据“部署”计划的任务，并一次更改大量计算机上的本地管理员密码，这可能是两种最流行的使用方案。

2006年，Microsoft购买了Desktop Standard的“ PolicyMaker”，并对其进行了重新命名并随着Windows Server 2008一起发布，称为“组策略首选项”。组策略首选项（GPP）最有用的功能之一是能够在几种情况下存储和使用凭据。这些包括：

> ```text
> 映射驱动（Drives.xml）
> ​​​​创建本地用户
> 数据源（DataSources.xml）
> 打印机配置（Printers.xml）
> 创建/更新服务（Services.xml）
> 计划任务（ScheduledTasks.xml）
> 更改本地Administrator密码
> ```

### **组策略首选项中的凭据存储**

我们使用组策略首选项来进行修改密码时也会面临一个问题，数据如何被保护起来？

在管理员创建了一个新的GPP时，SYSVOL里有一个XML文件提供了相关的数据配置，其中密码被以AES-256的加密算法加密而保护。但目前看起来也不那么安全了。在2012年，微软在[MSDN上发布了AES的私钥](https://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be.aspx)，它可以用来解密下列在SYSVOL中的密码。

![](https://img-blog.csdnimg.cn/20201004163935395.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

![](https://img-blog.csdnimg.cn/20201004165248215.png)

![](https://img-blog.csdnimg.cn/2020100416474556.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

**注意：**

此处仅为实验，在生产环境中修改组策略请慎重，上述图片仅为展示。

### 解密

这里使用PowerSploit函数[Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)对组策略首选项的密码进行解密。屏幕截图显示了类似的PowerShell功能，该功能从SYSVOL中的XML文件中解密GPP密码

![](https://img-blog.csdnimg.cn/20201004170143371.png)

当然，也有人已经给出了一个快速的搜索方法：

```text
findstr /S /I cpassword \\Win-ocbqn1epquf\sysvol\pingpig.com\Policies\*.xml
```

![](https://img-blog.csdnimg.cn/20201004170407406.png)

## 防御

* 在用于管理GPO的每台计算机上安装KB2962486，以防止将新凭据放置在组策略首选项中。
* 删除SYSVOL中包含密码的现有GPP xml文件。

### **GPP凭证补丁\(KB2962486\)**

2014年5月13日，微软发布了[MS14-025的补丁KB2962486，即那个GPP导致的权限提升漏洞](https://support.microsoft.com/en-us/kb/2962486)。这个补丁需要安装在所有使用了RSAT的系统上，防止管理将密码数据放进GPP里

### **GPP利用检查**

**XML权限拒绝检查：**

```text
把新的xml文件放到SYSVOL里时，访问的权限为设置拒绝Everyone。
审核访问被拒绝错误
如果不存在关联的GPO，则没有合法的访问权限
```

### **微软本地Administrator密码解决方案（LAPS）**

Microsoft提供的最好的更改本地管理员密码的方法是[“本地管理员密码解决方案”，也称为LAPS](https://adsecurity.org/?p=1790)。

