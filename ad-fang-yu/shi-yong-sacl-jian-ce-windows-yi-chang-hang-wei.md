# 使用SACL检测Windows异常行为



## 讲在前面

通过这篇文章来介绍如何使用[系统访问控制列表（SACL）](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-control-lists)功能检测Windows主机上的异常活动，而不仅仅是只关注异常进程或线程

## ACE和ACL简介 <a id="9c30"></a>

注意：这是笔者在阅读微软文档后进行的自我理解，对于ACE和ACL的知识强烈建议读者各自深入去理解和实际。这里只做简单介绍

* （访问控制项-Access Control Entries） 
* （访问控制列表-Access Control Lists） 

在Windows的世界里，ACL是可以包含零个、一个或多个ACE列表结构，ACL中的每个ACE描述了一个安全标识符（SID）和针对给定对象的该SID允许的特定访问（或拒绝）权限。例如，一个ACE可以允许特定的用户读取/写入/修改对象，而另一个ACE可以完全拒绝其他用户对该对象的访问。ACL应用于安全对象，例如文件，文件夹，注册表项和内核对象。

**ACL可以是以下两种特定变体之一：**  


* **自由访问控制列表**（DACL） 
* **系统访问控制列表**（SACL） 

DACL主要用于控制对对象的访问，而SACL主要用于记录对对象的访问尝试。

## 举个例子

为“新建文本文档.txt”添加SACL  


注意:您将需要启用适当的Windows事件日志记录，以便记录对象操作事件ID，笔者这里共享一份普通的GPO策略，读者可实验中自行导入更新即可。

* 选择新建文本文档.txt，然后右键单击&gt;属性 
* 单击安全选项卡。
* 单击高级。
* 单击审核选项卡、添加审核用户（笔者这里选择添加everyone用户）
* 然后对审核用户添加“列表文件夹/读取数据”权限即可

![](https://img-blog.csdnimg.cn/20201021005028287.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


## 验证区别 

我们正常打开文件查看是右边的显示，左边则是模拟恶意程序例如以cmd.exe增删查改此文档就会被记录以cmd.exe对此文件的活动。在这种情况下，SACL起作用并且记录了我们的恶意二进制文件试图访问我们的敏感文档。我们可以通过查找访问此文件的异常进程来对这些数据进行操作。

![](https://img-blog.csdnimg.cn/20201021004547353.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


## SACL的预警和检测策略

我们可以对敏感的文件配置适当的SACL来增进我们的预警效率和针对其制定相关检测策略，例如如下的部分威胁情况：  


### 浏览器数据收集 <a id="f2d7"></a>

> **检测策略**：确定非浏览器进程何时访问敏感的浏览器文件，数据库和文件夹。
>
> **SACL基本功能**：对象读取
>
> **正常活动**：浏览器进程（例如Chrome和Firefox）将例行访问这些文件。
>
> **可能的活动**：询问浏览器历史记录，盗窃浏览器cookie，盗窃浏览器登录数据等。

### 密钥和凭证收集 

> **检测策略**：标记非合法进程何时访问用户主目录中的敏感文件，密钥和凭据存储。  
>
>
> **SACL基本功能**：对象读取  
>
>
> **正常活动**：密码库，SSH / SSH密钥管理器二进制文件，GPG二进制文件，管理工具。  
>
>
> **可能的活动**：盗窃SSH / GPG密钥，盗窃密码库，盗窃AWS / Azure凭据等。

### 注册表持久性  <a id="9cf4"></a>

> **检测策略**：识别常见滥用注册表位置中的恶意持久性（或对合法持久性条目的恶意修改）。
>
> **SACL基本功能**：对象写入
>
> **正常活动**：取决于软件安装和行为的变量。
>
> **可能获的活动**：添加新的恶意二进制运行密钥条目，劫持恶意恶意持久性条目等。

### 恶意系统篡改 <a id="7203"></a>

> **警报和检测策略**：确定对关键系统安全性，日志记录或保护性控件进行恶意修改的时间。
>
> **SACL基元**：对象写入
>
> **基准活动**：GPO活动，正常的管理更改。
>
> **捕获的活动**：[修改信任库\[PDF\]](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)，修改日志记录（例如，命令行，powershell），操纵安全工具控件（例如，sysmon配置）等。

## 总结 

在实际环境部署时，应当注意如下部分几点：  


* 针对必要的文件或对象进行SACL设置，不可滥用。
* 应当结合windows事件日志一起分析，不能仅依赖日志的分析

