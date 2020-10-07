# 部分内网工具

## 讲在前面

这篇文章主要会讲我们在内网渗透时频繁使用最多的工具，当然该列表是国外的优秀研究员总结而成，笔者在这里进行自我消化后呈现给大家，望斧正勘误。[红队工具部分集合](https://xz.aliyun.com/t/7226#toc-0)

## 常用工具：

## [Mimikatz](https://github.com/gentilkiwi/mimikatz)：评估Windows安全的一款工具 

## [Kekeo](https://github.com/gentilkiwi/kekeo)

## [Rubeus](https://github.com/GhostPack/Rubeus): kekeo的C\#版本

笔者在使用到该工具的时候是利用ASEPRoasting漏洞时，利用其获取指定用户的hash，如果执行该程序时不在域内，则必须指定域名，域控制器，OU等内容

## [ADRecon](https://github.com/sense-of-security/ADRecon): 探测AD域信息的powershell工具

## \*\*\*\*[**Bloodhound**](https://github.com/BloodHoundAD/BloodHound/releases/tag/3.0.5)**: 自动生成AD域内的网络拓扑**

该工具可以将域内的关系以图形化的方式显示，形象生动的展现给攻击者或防守者，对于双方来说都会有不同的感觉，当然笔者在这里不会深入详细的介绍，深入使用请君自研。

### [python版本的猎狗](https://github.com/fox-it/BloodHound.py)

#### **安装**

```text
git clone https://github.com/fox-it/BloodHound.py.git 
cd BloodHound.py/&&pip install
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

#### **使用**

```text
python bloodhound.py  -d pingpig.com -u administrator -p win@123 -gc WIN-OCBQN1EPQUF.pingpig.com  -c all
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![](https://img-blog.csdnimg.cn/20201007220112467.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​脚本执执完毕后，它将生成几个json格式的文件，复制这些文件，将它们拖到[Bloodhound](https://github.com/BloodHoundAD/BloodHound/releases/tag/3.0.5)中，现在您就有了一个漂亮的网络图，可以自行在工具内选择不同的筛选条件得到自己满意的结果。

#### [Bloodhound](https://github.com/BloodHoundAD/BloodHound/releases/tag/3.0.5)的准备工作：

* jdk11.0
* powershell.3.0以上版本
* neo4j数据库安装

 ![](https://img-blog.csdnimg.cn/20201007225834522.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

#### 安装过程会出现的问题：

[neo4j数据库安装问题](https://blog.csdn.net/moxiaobeimm/article/details/87275756)

安装好后进入登录界面将json文件拖入即可

![](https://img-blog.csdnimg.cn/20201007230100181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


## \*\*\*\*[**CrackMapExec**](https://github.com/byt3bl33d3r/CrackMapExec)**:评估大型AD网络的安全性**

工具相对来说较为成熟，作者对于工具的使用已经形成文档上传到gitbook上，这里笔者以windows版本的[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)举例

### kali下安装

> apt-get install crackmapexec  
> apt-get install -y libssl-dev libffi-dev python-dev build-essential  
> pip install --user pipenv  
> git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec  
> cd CrackMapExec && pipenv install  
> pipenv shell  
> python setup.py install

### 使用

> 进入CrackMapExec目录，执行pipenv shell

部分用例

> \#\#\#\#　列出共享  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --shares  
> \#\#\#\#　列出会话  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --sessions  
> \#\#\#\#　列出磁盘信息  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --disks  
> \#\#\#\#　列出登录的用户  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --loggedon-users  
> \#\#\#\#　列出域用户  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --users  
> \#\#\#\#　根据唯一的RID列出所有的用户  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --rid-brute  
> \#\#\#\#　列出域组  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --groups  
> \#\#\#\#  列出本地组  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --local-groups  
> \#\#\#\#　列出域密码策略  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --pass-pol  
> \#\#\#\#　尝试空会话  
> cme smb 192.168.1.111 -u '' -p ''  
> \#\#\#\#　列出指定域信息  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -d LABNET  
> \#\#\#\#　列出ntds.dit的历史信息  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --ntds-history  
> \#\#\#\#　爬行C盘目录信息  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --spider C\$ --pattern txt  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' --spider C\$
>
> \#\#\#\#　远程执行命令  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -X '$PSVersionTable' --exec-method wmiexec  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -X '$set' --exec-method wmiexec  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -X '$whoami' --exec-method wmiexec  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -X 'whoami' --exec-method wmiexec  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -X 'ipconfig /all' --exec-method wmiexec  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -X 'tasklist /svc' --exec-method wmiexec  
> cme smb 192.168.1.111 -u admin -p 'xxxeeee' -x ipconfig

\*\*\*\*[**DeathStar**](https://github.com/byt3bl33d3r/DeathStar)**: AD渗透的Python脚本**

直译过来为死亡之星，可惜该项目在去年已经不在维护，也就不在支持同Empire的联动了。不过有读者想要继续该研究的，这里还有人在维护[DeathStar](https://github.com/byt3bl33d3r/DeathStar)与[Empire](https://github.com/byt3bl33d3r/Empire)

下载回来后首先执行

```text
python empire --rest --username username --password password
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

这就会启动Empire命令行以及RESTfulAPI服务。  
使用以下命令启动Deathstar：  


```text
git clone https://github.com/byt3bl33d3r/DeathStar
# Death Star is written in Python 3
pip3 install -r requirements.txt
# Supply the username and password you started Empire's RESTful API with
./DeathStar.py -u username -p password
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

Death Star会创建一个http侦听，然后你会看到一个’Polling for Agents’代理状态，这就意味着你已经连接上了Empire的RESTfulAPI，然后DeathStar在等待第一个Agent。一旦得到一个在域中的agent，Deathstar就会对它进行接管，然后就会开始攻击。  


## [Impacket](https://github.com/SecureAuthCorp/impacket): 渗透测试的python工具集

相信大多数攻击人员都会使用该工具集，目前该工具已经集成到kali上，你也可以在github上下载[最新版本](https://github.com/SecureAuthCorp/impacket)。

工具集内集成了非常多类型漏洞的脚本，相对内网渗透来说，能把impacket包内的工具利用熟练以及了解原理就很不错。

介绍一篇译文：[impacket介绍](https://www.cnblogs.com/backlion/p/10676339.html)

* [Inveigh](https://github.com/Kevin-Robertson/Inveigh): powershell攻击脚本

利用名称解析协议中的缺陷进行内网渗透是执行中间人（MITM）攻击的常用技术。有两个特别容易受到攻击的名称解析协议分别是链路本地多播名称解析（LLMNR）和NetBIOS名称服务（NBNS）。AD环境中默认启用了LLMNR和NBNS，这使得这种类型的欺骗攻击将会成为一种非常有效的方式，既可以获得对域的初始访问权限，也可以在漏洞后期利用过程中提升域权限。Inveigh是PowerShell ADIDNS / LLMNR / NBNS / mDNS / DNS欺骗程序和中间人工具  


```text
 Invoke-Inveigh -ConsoleOutput Y
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

 一篇译文：[inveigh介绍](https://www.4hou.com/posts/r9PK)

## \*\*\*\*[**PingCastle**](https://www.pingcastle.com/download/)**: 评估AD安全性的工具**

> 【扫描指定域名】
>
> PingCastle --healthcheck --server www.example.com
>
> 【生成密钥对】
>
> PingCastle.exe --gemerate-key //生成的密钥对可以去config文件看
>
> 【生成报告】
>
> PingCastle --hc-conso //注意！要在交互模式下输入"conso"
>
> 【生成xlsx数据表】
>
> PingCastleReporting --gc-template //注意！要在交互模式下输入"template"
>
> 【生成数据视图】
>
> PingCastleReporting --gc-overview

## \*\*\*\*[**PowerView**](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)**: 探测AD域信息的powershell工具**

目前来说利用powerview工具会解决我们在渗透中的大部分问题，它的确是一个非常不错的工具，但是需要注意的是该工具依然会有很多不完善的地方，需要各位读者深入研究提出自己的意见。

这里推荐一篇实用的文章：[powerview实操](https://blog.csdn.net/prettyX/article/details/103874602)

## 

## [PSAttack](https://github.com/jaredhaight/PSAttack): 直接调用.net框架的poweshell攻击工具，其不依赖powershell.exe

PSattack是一个开源的，将渗透测试实践过程中所有的脚本结合起来形成的框架。更有趣的是使用攻击类型的PowerShell脚本并不会调用powershell.exe，而是通过.NET框架直接调用的PowerShell。另外，所有的模块都是加密处理的，并且不会写入到硬盘当中，所以在一定程度上可以做到免杀。  


在命令上国内已经有译者整理完毕了：[psattack](https://zhuanlan.zhihu.com/p/27879198)

## \*\*\*\*[**Responder**](https://github.com/SpiderLabs/Responder)**: 通常被用来进行netlm-rela中继或网络投毒攻击**

**当网络上的设备尝试用LLMNR和NBT-NS请求来解析目标机器时，Responder就会伪装成目标机器。当受害者机器尝试登陆攻击者机器，responder就可以获取受害者机器用户的NTLMv2哈希值。**  


在笔者看来，国内许多文章都是利用其来在域内捕获MTLMv2Hash

部分国内译者文章：[responder利用](https://www.freebuf.com/articles/system/194549.html)

当然各位读者也可以自行深入研究探讨

## \*\*\*\*[**Seatbelt**](https://github.com/GhostPack/Seatbelt)**: AD域内安全评估工具**

Seatbelt是一个C＃项目，它从攻击性和防御性安全角度执行许多面向安全的主机调查“安全检查”。需要自行编译打包。  


## [SharpSploit](https://github.com/cobbr/SharpSploit): PowerSploit的C\#版本

需要自行编译打包，我们可以参考这篇并不是翻译的很好的文章：[sharpsploit功能详解](https://www.bus123.net/post/8893.html)

